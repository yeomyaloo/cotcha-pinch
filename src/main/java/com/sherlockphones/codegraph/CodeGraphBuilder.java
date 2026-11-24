package com.sherlockphones.codegraph;

import com.codeagent.core.java.JavaGraphSupport;
import com.codeagent.core.java.JavaProject;
import com.codeagent.core.java.JavaProject.MethodInfo;
import com.codeagent.core.java.JavaProject.TypeInfo;
import com.codeagent.core.kotlin.KotlinGraphSupport;
import com.codeagent.core.kotlin.KotlinProject;
import com.codeagent.core.kotlin.KotlinProject.KotlinFunction;
import com.codeagent.core.kotlin.KotlinProject.KotlinType;
import com.codeagent.core.model.CodeEdgeKind;
import com.codeagent.core.model.CodeGraphDraft;
import com.codeagent.core.model.CodeGraphDraft.NodeDraft;
import com.codeagent.core.model.CodeNodeKind;
import com.codeagent.core.rules.SinkRule;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 모바일 앱의 코드 그래프를 만든다. Java·Kotlin 파싱·구조·호출 연결은 공용 엔진 cotcha-trail(core-code-agent)의
 * {@link JavaGraphSupport}·{@link KotlinGraphSupport} 가 맡고,
 * 여기서는 앱 고유의 것만 더한다: 외부에 열린 컴포넌트와 JS 브리지(진입점), 플랫폼 위험 지점 규칙(AppScan),
 * 아무 인증서나 믿는 TLS 구현, 줄 단위·설정 위험 지점.
 */
public class CodeGraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(CodeGraphBuilder.class);

    private static final Set<String> TRUST_MANAGERS = Set.of("javax.net.ssl.X509TrustManager", "javax.net.ssl.X509ExtendedTrustManager");
    private static final String HOSTNAME_VERIFIER = "javax.net.ssl.HostnameVerifier";
    private static final Map<String, Object> CODE = Map.of("detector", "code");

    private final JavaProject project;
    private final KotlinProject kotlin;
    private final KotlinGraphSupport kotlinSupport;
    private final AppScan scan;
    private final CodeGraphDraft draft = new CodeGraphDraft();
    private final JavaGraphSupport support;
    /** 모든 인증서·호스트를 믿는 프로젝트 클래스 → 그 위험 지점 노드 키 */
    private final Map<String, String> trustAllTypes = new HashMap<>();

    public CodeGraphBuilder(JavaProject project, KotlinProject kotlin, AppScan scan) {
        this.project = project;
        this.kotlin = kotlin;
        this.scan = scan;
        this.support = new JavaGraphSupport(project, draft, scan.knownReturnTypes());
        this.kotlinSupport = new KotlinGraphSupport(kotlin, draft, scan.knownReturnTypes());
    }

    public CodeGraphDraft build() {
        project.types().forEach(support::addStructure);
        kotlin.types().forEach(kotlinSupport::addStructure);
        project.types().forEach(support::addOverrides);
        kotlin.types().forEach(kotlinSupport::addOverrides);
        project.types().forEach(this::addTrustAll);
        scan.components().forEach(this::addComponent);
        project.types().forEach(this::addBridges);
        kotlin.types().forEach(this::addKotlinBridges);
        project.types().forEach(t -> t.methods().forEach(this::addCalls));
        kotlin.types().forEach(t -> t.functions().forEach(f -> kotlinSupport.addCalls(f, scan::match, CODE)));
        scan.staticSinks().forEach(this::addStaticSink);
        maskSnippets();
        return draft;
    }

    /** 코드 조각은 도구 출력·보고서로 나가므로 비밀값을 가린다 (new SecretKeySpec("…") 의 키 등) */
    @SuppressWarnings("unchecked")
    private void maskSnippets() {
        for (NodeDraft node : draft.nodes()) {
            if (node.kind() != CodeNodeKind.SINK || !(node.props().get("snippet") instanceof String snippet)) {
                continue;
            }
            String cwe = String.valueOf(node.props().get("cwe"));
            String masked = SecretMasker.mayHoldSecretLiteral(cwe) ? SecretMasker.maskLiterals(snippet) : SecretMasker.mask(snippet);
            if (!masked.equals(snippet)) {
                ((Map<String, Object>) node.props()).put("snippet", masked);
            }
        }
    }

    // ---- 진입점: 외부에 열린 컴포넌트 → 입력을 받는 메서드 ----

    private void addComponent(Component component) {
        Optional<TypeInfo> type = project.type(component.className());
        Map<String, Object> props = new LinkedHashMap<>(component.props());
        props.put("kind", component.kind());
        props.put("component", component.className());
        props.put("declaredIn", component.declaredIn() + ":" + component.line());

        List<MethodInfo> handlers = new ArrayList<>();
        if (type.isPresent()) {
            List<TypeInfo> lineage = new ArrayList<>();
            lineage.add(type.get());
            lineage.addAll(project.ancestors(type.get()));
            for (String name : component.handlerMethods()) {
                // 가장 가까운 클래스에서 재정의한 것만 (부모 클래스의 onCreate 는 자식이 super 로 부를 때 호출 관계로 이어진다)
                lineage.stream()
                        .map(t -> t.methods().stream().filter(m -> m.name().equals(name)).toList())
                        .filter(found -> !found.isEmpty())
                        .findFirst()
                        .ifPresent(handlers::addAll);
            }
        }
        Optional<KotlinType> kotlinType = type.isPresent() ? Optional.empty() : kotlin.type(component.className());
        List<KotlinFunction> kotlinHandlers = new ArrayList<>();
        if (kotlinType.isPresent()) {
            List<KotlinType> lineage = new ArrayList<>();
            lineage.add(kotlinType.get());
            lineage.addAll(kotlin.ancestors(kotlinType.get()));
            for (String name : component.handlerMethods()) {
                lineage.stream()
                        .map(t -> t.functions().stream().filter(f -> f.name().equals(name)).toList())
                        .filter(found -> !found.isEmpty())
                        .findFirst()
                        .ifPresent(kotlinHandlers::addAll);
            }
        } else if (type.isEmpty() && !props.containsKey("source")) {
            props.put("source", "앱 소스에 클래스가 없음 (라이브러리 클래스이거나 Kotlin 파서를 쓸 수 없음). 호출 경로 없이 read_file·grep_code 로 볼 것");
        }
        List<String> handlerKeys = new ArrayList<>(handlers.stream().map(MethodInfo::key).toList());
        kotlinHandlers.forEach(f -> handlerKeys.add(f.key()));
        props.put("handlers", handlerKeys);

        String entryKey;
        if (type.isPresent()) {
            entryKey = draft.addNode(JavaGraphSupport.node(CodeNodeKind.ENTRY_POINT, component.label(), type.get().filePath(),
                    type.get().decl(), props));
        } else if (kotlinType.isPresent()) {
            entryKey = draft.addNode(new NodeDraft(CodeNodeKind.ENTRY_POINT, component.label(), kotlinType.get().filePath(),
                    kotlinType.get().startLine(), kotlinType.get().endLine(), props));
        } else {
            entryKey = draft.addNode(new NodeDraft(CodeNodeKind.ENTRY_POINT, component.label(), component.declaredIn(),
                    component.line(), component.line(), props));
        }
        handlers.forEach(h -> draft.addEdge(entryKey, JavaGraphSupport.methodKey(h), CodeEdgeKind.ROUTES_TO));
        kotlinHandlers.forEach(f -> draft.addEdge(entryKey, KotlinGraphSupport.methodKey(f), CodeEdgeKind.ROUTES_TO));
    }

    /** Kotlin 의 @JavascriptInterface 함수 */
    private void addKotlinBridges(KotlinType type) {
        for (KotlinFunction function : type.functions()) {
            if (function.annotations().stream().noneMatch(a -> scan.bridgeAnnotations().contains(a)
                    || scan.bridgeAnnotations().stream().anyMatch(b -> b.endsWith("." + a)))) {
                continue;
            }
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("kind", "JS_BRIDGE");
            props.put("component", type.fqn());
            props.put("handlers", List.of(function.key()));
            String entryKey = draft.addNode(new NodeDraft(CodeNodeKind.ENTRY_POINT, "JS_BRIDGE " + function.key(), type.filePath(),
                    function.startLine(), function.endLine(), props));
            draft.addEdge(entryKey, KotlinGraphSupport.methodKey(function), CodeEdgeKind.ROUTES_TO);
        }
    }

    /** @JavascriptInterface 메서드: WebView 에 띄운 웹 페이지의 자바스크립트가 부를 수 있다 */
    private void addBridges(TypeInfo type) {
        for (MethodInfo method : type.methods()) {
            boolean bridge = method.decl().getAnnotations().stream()
                    .anyMatch(a -> scan.bridgeAnnotations().contains(resolveAnnotation(type, a)));
            if (!bridge) {
                continue;
            }
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("kind", "JS_BRIDGE");
            props.put("component", type.fqn());
            props.put("handlers", List.of(method.key()));
            String entryKey = draft.addNode(JavaGraphSupport.node(CodeNodeKind.ENTRY_POINT, "JS_BRIDGE " + method.key(),
                    type.filePath(), method.decl(), props));
            draft.addEdge(entryKey, JavaGraphSupport.methodKey(method), CodeEdgeKind.ROUTES_TO);
        }
    }

    private static String resolveAnnotation(TypeInfo type, AnnotationExpr annotation) {
        String name = annotation.getNameAsString();
        String resolved = type.resolver().resolve(name);
        return resolved != null ? resolved : name;
    }

    // ---- 모든 인증서·호스트를 믿는 TLS 구현 ----

    /** X509TrustManager 를 구현하면서 checkServerTrusted 가 아무것도 확인하지 않는 클래스, true 만 돌려주는 HostnameVerifier */
    private void addTrustAll(TypeInfo type) {
        Set<String> lineage = project.lineage(type);
        boolean trustManager = lineage.stream().anyMatch(TRUST_MANAGERS::contains);
        boolean verifier = lineage.contains(HOSTNAME_VERIFIER);
        if (!trustManager && !verifier) {
            return;
        }
        for (MethodInfo method : type.methods()) {
            if (!(method.decl() instanceof MethodDeclaration decl)) {
                continue;
            }
            String api = null;
            if (trustManager && method.name().equals("checkServerTrusted") && acceptsEverything(decl)) {
                api = "X509TrustManager.checkServerTrusted (아무 인증서나 믿음)";
            } else if (verifier && method.name().equals("verify") && alwaysTrue(decl)) {
                api = "HostnameVerifier.verify (아무 호스트나 믿음)";
            }
            if (api != null) {
                String sinkKey = support.addSink(method, decl, new SinkRule(type.fqn(), Set.of(method.name()), "TLS", "CWE-295"), api, CODE);
                trustAllTypes.put(type.fqn(), sinkKey);
            }
        }
    }

    /** 예외를 던지지도, 다른 검증을 부르지도 않는 checkServerTrusted */
    private static boolean acceptsEverything(MethodDeclaration decl) {
        return decl.getBody().map(b -> b.findAll(ThrowStmt.class).isEmpty() && b.findAll(MethodCallExpr.class).isEmpty()).orElse(false);
    }

    /** return true 하나뿐인 verify */
    private static boolean alwaysTrue(MethodDeclaration decl) {
        return decl.getBody().map(b -> {
            List<ReturnStmt> returns = b.findAll(ReturnStmt.class);
            return !returns.isEmpty() && returns.stream().allMatch(r -> r.getExpression()
                    .filter(e -> e instanceof BooleanLiteralExpr bool && bool.getValue()).isPresent());
        }).orElse(false);
    }

    // ---- 호출 관계와 위험 지점 ----

    private void addCalls(MethodInfo caller) {
        for (MethodCallExpr call : caller.decl().findAll(MethodCallExpr.class)) {
            String targetType = call.getScope()
                    .map(scope -> support.typeOfScope(scope, caller))
                    .orElse(null);
            if (support.linkProjectCall(caller, call, targetType)) {
                continue;
            }
            String method = call.getNameAsString();
            Optional<SinkRule> sink = scan.match(targetType, method);
            if (sink.isPresent()) {
                support.addSink(caller, call, sink.get(), sink.get().api(method), CODE);
            } else if (targetType == null && call.getScope().isPresent()) {
                draft.countUnresolvedCall();
                log.debug("호출 대상 타입을 알 수 없음: {} ({})", call, caller.key());
            }
        }

        for (ObjectCreationExpr creation : caller.decl().findAll(ObjectCreationExpr.class)) {
            String type = caller.owner().resolver().resolve(creation.getType().getNameWithScope());
            scan.match(type, "<init>").ifPresent(rule -> support.addSink(caller, creation, rule, rule.api("<init>"), CODE));
            // 모든 인증서를 믿는 클래스를 만드는 곳 → 그 위험 지점
            if (type != null && trustAllTypes.containsKey(type)) {
                draft.addEdge(JavaGraphSupport.methodKey(caller), trustAllTypes.get(type), CodeEdgeKind.CALLS);
            }
            creation.getAnonymousClassBody().ifPresent(body -> anonymousTrustAll(caller, creation, type, body));
        }
    }

    /** new X509TrustManager() { ... } 처럼 메서드 안에서 바로 만든 익명 클래스 */
    private void anonymousTrustAll(MethodInfo caller, ObjectCreationExpr creation, String type, List<BodyDeclaration<?>> body) {
        if (type == null) {
            return;
        }
        for (BodyDeclaration<?> member : body) {
            if (!(member instanceof MethodDeclaration decl)) {
                continue;
            }
            if (TRUST_MANAGERS.contains(type) && decl.getNameAsString().equals("checkServerTrusted") && acceptsEverything(decl)) {
                support.addSink(caller, creation, new SinkRule(type, Set.of("checkServerTrusted"), "TLS", "CWE-295"),
                        "X509TrustManager.checkServerTrusted (아무 인증서나 믿음)", CODE);
            } else if (HOSTNAME_VERIFIER.equals(type) && decl.getNameAsString().equals("verify") && alwaysTrue(decl)) {
                support.addSink(caller, creation, new SinkRule(type, Set.of("verify"), "TLS", "CWE-295"),
                        "HostnameVerifier.verify (아무 호스트나 믿음)", CODE);
            }
        }
    }

    // ---- 줄 단위·설정 위험 지점 ----

    /** Java 파일이면 그 줄을 감싼 메서드 아래에 달아 진입점 경로가 이어지게 하고, 아니면 파일 아래에 단다 */
    private void addStaticSink(StaticSink sink) {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("category", sink.category());
        props.put("cwe", sink.cwe());
        props.put("api", sink.api());
        props.put("snippet", sink.snippet());
        props.put("detector", sink.detector());

        Optional<MethodInfo> method = sink.filePath().endsWith(".java") ? methodAt(sink.filePath(), sink.line()) : Optional.empty();
        Optional<KotlinFunction> function = sink.filePath().endsWith(".kt") ? kotlinFunctionAt(sink.filePath(), sink.line()) : Optional.empty();
        String parentKey;
        if (method.isPresent()) {
            props.put("method", method.get().key());
            parentKey = JavaGraphSupport.methodKey(method.get());
        } else if (function.isPresent()) {
            props.put("method", function.get().key());
            parentKey = KotlinGraphSupport.methodKey(function.get());
        } else {
            String fileName = sink.filePath().substring(sink.filePath().lastIndexOf('/') + 1);
            props.put("method", fileName);
            parentKey = draft.addNode(new NodeDraft(CodeNodeKind.FILE, sink.filePath(), sink.filePath(), null, null, Map.of()));
        }
        String sinkKey = draft.addNode(new NodeDraft(CodeNodeKind.SINK,
                sink.filePath() + "@L" + sink.line() + ":" + sink.column() + " " + sink.api(),
                sink.filePath(), sink.line(), sink.line(), props));
        draft.addEdge(parentKey, sinkKey, method.isPresent() || function.isPresent() ? CodeEdgeKind.CALLS : CodeEdgeKind.CONTAINS);
    }

    private Optional<KotlinFunction> kotlinFunctionAt(String filePath, int line) {
        return kotlin.types().stream()
                .filter(t -> t.filePath().equals(filePath))
                .flatMap(t -> t.functions().stream())
                .filter(f -> f.startLine() <= line && f.endLine() >= line)
                .min((a, b) -> Integer.compare(a.endLine() - a.startLine(), b.endLine() - b.startLine()));
    }

    private Optional<MethodInfo> methodAt(String filePath, int line) {
        return project.types().stream()
                .filter(t -> t.filePath().equals(filePath))
                .flatMap(t -> t.methods().stream())
                .filter(m -> m.decl().getBegin().map(p -> p.line <= line).orElse(false)
                        && m.decl().getEnd().map(p -> p.line >= line).orElse(false))
                // 중첩 클래스의 메서드가 바깥 메서드보다 좁으므로 가장 짧은 범위를 고른다
                .min((a, b) -> Integer.compare(span(a), span(b)));
    }

    private static int span(MethodInfo m) {
        return m.decl().getEnd().map(p -> p.line).orElse(0) - m.decl().getBegin().map(p -> p.line).orElse(0);
    }
}
