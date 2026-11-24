package com.sherlockphones.codegraph;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.resolution.types.ResolvedType;
import com.sherlockphones.codegraph.CodeGraphDraft.NodeDraft;
import com.sherlockphones.codegraph.JavaProject.MethodInfo;
import com.sherlockphones.codegraph.JavaProject.TypeInfo;
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
 * 파싱된 Java 소스와 플랫폼 재료(AppScan)로 코드 그래프를 만든다.
 * 진입점은 외부에 열린 컴포넌트(매니페스트)와 웹 콘텐츠가 부를 수 있는 메서드(JS 브리지)다.
 */
public class CodeGraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(CodeGraphBuilder.class);

    private static final int SNIPPET_MAX_LENGTH = 300;
    private static final Set<String> TRUST_MANAGERS = Set.of("javax.net.ssl.X509TrustManager", "javax.net.ssl.X509ExtendedTrustManager");
    private static final String HOSTNAME_VERIFIER = "javax.net.ssl.HostnameVerifier";

    private final JavaProject project;
    private final AppScan scan;
    private final CodeGraphDraft draft = new CodeGraphDraft();
    /** 모든 인증서·호스트를 믿는 프로젝트 클래스 → 그 위험 지점 노드 키 */
    private final Map<String, String> trustAllTypes = new HashMap<>();

    public CodeGraphBuilder(JavaProject project, AppScan scan) {
        this.project = project;
        this.scan = scan;
    }

    public CodeGraphDraft build() {
        project.types().forEach(this::addStructure);
        project.types().forEach(this::addOverrides);
        project.types().forEach(this::addTrustAll);
        scan.components().forEach(this::addComponent);
        project.types().forEach(this::addBridges);
        project.types().forEach(t -> t.methods().forEach(this::addCalls));
        scan.staticSinks().forEach(this::addStaticSink);
        return draft;
    }

    // ---- 구조: FILE → CLASS → METHOD ----

    private void addStructure(TypeInfo type) {
        String fileKey = draft.addNode(new NodeDraft(CodeNodeKind.FILE, type.filePath(), type.filePath(), null, null, Map.of()));
        String classKey = draft.addNode(node(CodeNodeKind.CLASS, type.fqn(), type.filePath(), type.decl(), Map.of(
                "declaration", declarationKind(type.decl()),
                "annotations", annotations(type.decl()),
                "superTypes", type.superTypes())));

        Optional<String> outer = type.decl().getParentNode()
                .filter(p -> p instanceof TypeDeclaration<?>)
                .flatMap(p -> ((TypeDeclaration<?>) p).getFullyQualifiedName());
        draft.addEdge(outer.map(o -> CodeGraphDraft.key(CodeNodeKind.CLASS, o)).orElse(fileKey), classKey, CodeEdgeKind.CONTAINS);

        for (MethodInfo method : type.methods()) {
            String methodKey = draft.addNode(node(CodeNodeKind.METHOD, method.key(), type.filePath(), method.decl(), Map.of(
                    "name", method.name(),
                    "annotations", annotations(method.decl()))));
            draft.addEdge(classKey, methodKey, CodeEdgeKind.CONTAINS);
        }
    }

    private void addOverrides(TypeInfo type) {
        for (TypeInfo ancestor : project.ancestors(type)) {
            for (MethodInfo method : type.methods()) {
                if (method.isConstructor()) {
                    continue;
                }
                ancestor.methods().stream()
                        .filter(m -> m.name().equals(method.name()) && m.paramTypes().size() == method.paramTypes().size())
                        .forEach(m -> draft.addEdge(methodKey(m), methodKey(method), CodeEdgeKind.OVERRIDDEN_BY));
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
        } else {
            props.put("source", "Java 소스 없음 (Kotlin 이거나 라이브러리 클래스). 호출 경로 없이 read_file·grep_code 로 볼 것");
        }
        props.put("handlers", handlers.stream().map(MethodInfo::key).toList());

        String entryKey = type
                .map(t -> draft.addNode(node(CodeNodeKind.ENTRY_POINT, component.label(), t.filePath(), t.decl(), props)))
                .orElseGet(() -> draft.addNode(new NodeDraft(CodeNodeKind.ENTRY_POINT, component.label(), component.declaredIn(),
                        component.line(), component.line(), props)));
        handlers.forEach(h -> draft.addEdge(entryKey, methodKey(h), CodeEdgeKind.ROUTES_TO));
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
            String entryKey = draft.addNode(node(CodeNodeKind.ENTRY_POINT, "JS_BRIDGE " + method.key(), type.filePath(), method.decl(), props));
            draft.addEdge(entryKey, methodKey(method), CodeEdgeKind.ROUTES_TO);
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
                String sinkKey = addSink(method, decl, new SinkRule(type.fqn(), Set.of(method.name()), "TLS", "CWE-295"), api, "code");
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
                    .map(scope -> typeOfScope(scope, caller))
                    .orElse(null);

            if (call.getScope().isEmpty()) {
                // 스코프 없는 호출: 자기 클래스 → 바깥 클래스 순으로 찾는다
                if (linkProjectCall(caller, enclosingTypes(caller), call)) {
                    continue;
                }
            } else if (project.isProjectType(targetType)) {
                if (linkProjectCall(caller, List.of(targetType), call)) {
                    continue;
                }
            }

            String method = call.getNameAsString();
            Optional<SinkRule> sink = scan.match(targetType, method);
            if (sink.isPresent()) {
                addSink(caller, call, sink.get(), sink.get().api(method), "code");
            } else if (targetType == null && call.getScope().isPresent()) {
                draft.countUnresolvedCall();
                log.debug("호출 대상 타입을 알 수 없음: {} ({})", call, caller.key());
            }
        }

        for (ObjectCreationExpr creation : caller.decl().findAll(ObjectCreationExpr.class)) {
            String type = caller.owner().resolver().resolve(creation.getType().getNameWithScope());
            scan.match(type, "<init>").ifPresent(rule -> addSink(caller, creation, rule, rule.api("<init>"), "code"));
            // 모든 인증서를 믿는 클래스를 만드는 곳 → 그 위험 지점
            if (type != null && trustAllTypes.containsKey(type)) {
                draft.addEdge(methodKey(caller), trustAllTypes.get(type), CodeEdgeKind.CALLS);
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
                addSink(caller, creation, new SinkRule(type, Set.of("checkServerTrusted"), "TLS", "CWE-295"),
                        "X509TrustManager.checkServerTrusted (아무 인증서나 믿음)", "code");
            } else if (HOSTNAME_VERIFIER.equals(type) && decl.getNameAsString().equals("verify") && alwaysTrue(decl)) {
                addSink(caller, creation, new SinkRule(type, Set.of("verify"), "TLS", "CWE-295"),
                        "HostnameVerifier.verify (아무 호스트나 믿음)", "code");
            }
        }
    }

    private boolean linkProjectCall(MethodInfo caller, List<String> candidateTypes, MethodCallExpr call) {
        for (String type : candidateTypes) {
            List<MethodInfo> targets = project.findMethods(type, call.getNameAsString(), call.getArguments().size());
            if (!targets.isEmpty()) {
                targets.forEach(t -> draft.addEdge(methodKey(caller), methodKey(t), CodeEdgeKind.CALLS));
                return true;
            }
        }
        return false;
    }

    private String addSink(MethodInfo caller, Node expr, SinkRule rule, String api, String detector) {
        int line = expr.getBegin().map(p -> p.line).orElse(0);
        int column = expr.getBegin().map(p -> p.column).orElse(0);
        String snippet = expr instanceof MethodDeclaration decl ? decl.getDeclarationAsString(false, false, true) : expr.toString();
        if (snippet.length() > SNIPPET_MAX_LENGTH) {
            snippet = snippet.substring(0, SNIPPET_MAX_LENGTH) + "...";
        }
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("category", rule.category());
        props.put("cwe", rule.cwe());
        props.put("api", api);
        props.put("method", caller.key());
        props.put("snippet", snippet);
        props.put("detector", detector);

        String sinkKey = draft.addNode(new NodeDraft(CodeNodeKind.SINK, caller.key() + "@L" + line + ":" + column + " " + api,
                caller.owner().filePath(), line, expr.getEnd().map(p -> p.line).orElse(line), props));
        draft.addEdge(methodKey(caller), sinkKey, CodeEdgeKind.CALLS);
        return sinkKey;
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
        String parentKey;
        if (method.isPresent()) {
            props.put("method", method.get().key());
            parentKey = methodKey(method.get());
        } else {
            String fileName = sink.filePath().substring(sink.filePath().lastIndexOf('/') + 1);
            props.put("method", fileName);
            parentKey = draft.addNode(new NodeDraft(CodeNodeKind.FILE, sink.filePath(), sink.filePath(), null, null, Map.of()));
        }
        String sinkKey = draft.addNode(new NodeDraft(CodeNodeKind.SINK,
                sink.filePath() + "@L" + sink.line() + ":" + sink.column() + " " + sink.api(),
                sink.filePath(), sink.line(), sink.line(), props));
        draft.addEdge(parentKey, sinkKey, method.isPresent() ? CodeEdgeKind.CALLS : CodeEdgeKind.CONTAINS);
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

    // ---- 타입 알아내기 ----

    /**
     * 호출 대상 표현식의 타입 FQN을 구한다.
     * 변수·필드 선언과 import 문을 먼저 보고(라이브러리 jar 없이 동작), 안 되면 symbol solver에 맡긴다.
     */
    private String typeOfScope(Expression scope, MethodInfo context) {
        TypeInfo owner = context.owner();
        if (scope.isThisExpr()) {
            return owner.fqn();
        }
        if (scope.isSuperExpr()) {
            return owner.superTypes().isEmpty() ? null : owner.superTypes().get(0);
        }
        if (scope instanceof NameExpr name) {
            String variableType = variableType(name.getNameAsString(), context);
            if (variableType != null) {
                return variableType;
            }
            String staticType = owner.resolver().resolve(name.getNameAsString());
            if (staticType != null) {
                return staticType;
            }
        }
        if (scope instanceof ObjectCreationExpr creation) {
            String createdType = JavaProject.resolveType(creation.getType(), owner.resolver());
            if (createdType != null) {
                return createdType;
            }
        }
        if (scope instanceof FieldAccessExpr field && field.getScope().isThisExpr()) {
            String fieldType = project.fieldType(owner, field.getNameAsString());
            if (fieldType != null) {
                return fieldType;
            }
        }
        String solved = solve(scope);
        if (solved == null && scope instanceof MethodCallExpr call) {
            // getIntent().getStringExtra(...) 처럼 프레임워크 메서드가 돌려준 값: 라이브러리 jar 가 없어도 반환 타입을 안다
            return scan.knownReturnTypes().get(call.getNameAsString());
        }
        return solved;
    }

    private String variableType(String name, MethodInfo context) {
        TypeResolver resolver = context.owner().resolver();
        for (VariableDeclarator variable : context.decl().findAll(VariableDeclarator.class)) {
            if (variable.getNameAsString().equals(name)) {
                if (variable.getType().isVarType()) {
                    return variable.getInitializer().map(this::solve).orElse(null);
                }
                return JavaProject.resolveType(variable.getType(), resolver);
            }
        }
        for (Parameter parameter : context.decl().findAll(Parameter.class)) {
            if (parameter.getNameAsString().equals(name) && !parameter.getType().isUnknownType()) {
                return JavaProject.resolveType(parameter.getType(), resolver);
            }
        }
        for (String typeFqn : enclosingTypes(context)) {
            String fieldType = project.type(typeFqn).map(t -> project.fieldType(t, name)).orElse(null);
            if (fieldType != null) {
                return fieldType;
            }
        }
        return null;
    }

    private List<String> enclosingTypes(MethodInfo method) {
        List<String> result = new ArrayList<>();
        Node current = method.owner().decl();
        while (current != null) {
            if (current instanceof TypeDeclaration<?> td) {
                td.getFullyQualifiedName().ifPresent(result::add);
            }
            current = current.getParentNode().orElse(null);
        }
        return result;
    }

    private String solve(Expression expr) {
        try {
            ResolvedType type = expr.calculateResolvedType();
            return type.isReferenceType() ? type.asReferenceType().getQualifiedName() : null;
        } catch (RuntimeException | StackOverflowError e) {
            return null;
        }
    }

    // ---- 헬퍼 ----

    private static String methodKey(MethodInfo method) {
        return CodeGraphDraft.key(CodeNodeKind.METHOD, method.key());
    }

    private static NodeDraft node(CodeNodeKind kind, String qualifiedName, String filePath, Node astNode, Map<String, Object> props) {
        Integer begin = astNode.getBegin().map(p -> p.line).orElse(null);
        Integer end = astNode.getEnd().map(p -> p.line).orElse(null);
        return new NodeDraft(kind, qualifiedName, filePath, begin, end, props);
    }

    private static List<String> annotations(NodeWithAnnotations<?> node) {
        return node.getAnnotations().stream().map(a -> a.getName().getIdentifier()).toList();
    }

    private static String declarationKind(TypeDeclaration<?> decl) {
        if (decl.isClassOrInterfaceDeclaration()) {
            return decl.asClassOrInterfaceDeclaration().isInterface() ? "interface" : "class";
        }
        if (decl.isEnumDeclaration()) {
            return "enum";
        }
        if (decl.isRecordDeclaration()) {
            return "record";
        }
        return "annotation";
    }
}
