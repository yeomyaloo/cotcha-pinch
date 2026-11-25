package com.sherlockphones.tools;

import com.sherlockphones.android.AndroidManifests.Manifest;
import com.sherlockphones.codegraph.CodeGraph;
import com.sherlockphones.codegraph.CodeGraph.Node;
import com.sherlockphones.codegraph.CodeGraph.SinkPath;
import com.codeagent.core.model.CodeNodeKind;
import com.sherlockphones.codegraph.StaticSink;
import com.sherlockphones.dependency.DependencyHistory;
import com.sherlockphones.dependency.DependencyService;
import com.sherlockphones.dependency.OsvClient;
import com.sherlockphones.findings.Finding;
import com.sherlockphones.findings.Finding.Evidence;
import com.sherlockphones.findings.Finding.Status;
import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.findings.MobileMapping;
import com.sherlockphones.findings.Reports;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.LoadedApp;
import com.sherlockphones.workspace.Workspace;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.sherlockphones.tools.ToolDef.enumOf;
import static com.sherlockphones.tools.ToolDef.integer;
import static com.sherlockphones.tools.ToolDef.schema;
import static com.sherlockphones.tools.ToolDef.string;

/**
 * 채팅의 Claude 가 쓰는 도구 모음. Claude 가 판단(두뇌)을 맡고, 이 서버는 앱 불러오기·설정 검사·코드 그래프·파일 접근·기록(손발)을 맡는다.
 */
public class SherlockTools {

    private static final List<String> SEVERITIES = List.of("critical", "high", "medium", "low", "info");
    private static final List<String> CONFIDENCES = List.of("high", "medium", "low");
    private static final Map<String, Status> VERDICTS = Map.of(
            "confirmed", Status.CONFIRMED, "rejected", Status.REJECTED, "uncertain", Status.UNCERTAIN);
    private static final Map<String, Object> APP = string("load_app 이 돌려준 앱 id (예: bank-app)");
    private static final List<String> DETECTORS = List.of("code", "line", "config");

    private final Workspace workspace;
    private final AppRegistry registry;
    private final FindingStore findings;
    private final DependencyService dependencies;

    public SherlockTools(Workspace workspace, AppRegistry registry, FindingStore findings) {
        this(workspace, registry, findings, OsvClient.fromEnvironment());
    }

    public SherlockTools(Workspace workspace, AppRegistry registry, FindingStore findings, OsvClient osv) {
        this.workspace = workspace;
        this.registry = registry;
        this.findings = findings;
        this.dependencies = new DependencyService(osv, new DependencyHistory(workspace.dependencyScans()));
    }

    public List<ToolDef> all() {
        return List.of(loadApp(), listApps(), listComponents(), listSinkPaths(), listSinks(), checkConfig(), checkDependencies(),
                findCodeNodes(), getCallers(), getCallees(), readFile(), grepCode(), recordFinding(), submitVerdict(),
                listFindings(), exportReport(), clearFindings());
    }

    // ---- 앱 ----

    ToolDef loadApp() {
        return new ToolDef("load_app", "앱 불러오기",
                "분석할 모바일 앱 소스(안드로이드)를 불러와 매니페스트·설정 검사, 줄 단위 규칙, 코드 그래프(외부에 열린 컴포넌트 → 위험 지점)를 만든다. "
                        + "path(이 컴퓨터의 폴더) 또는 git_url(공개 https 저장소, 얕은 클론) 중 하나를 준다. "
                        + "같은 앱을 다시 부르면 다시 읽는다(Git 이면 최신 커밋으로 다시 클론). 분석의 첫 단계. 앱을 빌드하거나 실행하지 않는다.",
                schema(props(
                        "path", string("분석할 앱 폴더의 절대 경로 (Gradle 프로젝트 루트)"),
                        "git_url", string("공개 Git 저장소 https 주소 (github.com, gitlab.com, bitbucket.org)"),
                        "branch", string("git_url 의 브랜치. 생략하면 기본 브랜치"),
                        "name", string("앱 id 로 쓸 이름. 생략하면 폴더·저장소 이름")), List.of()),
                false, true, args -> {
            String path = args.optionalString("path").orElse(null);
            String gitUrl = args.optionalString("git_url").orElse(null);
            if ((path == null) == (gitUrl == null)) {
                throw new ToolException("path 와 git_url 중 하나만 줄 것");
            }
            String name = args.optionalString("name").orElse(null);
            LoadedApp app = gitUrl != null
                    ? registry.loadGit(gitUrl, args.optionalString("branch").orElse(null), name)
                    : registry.loadLocal(path, name);
            CodeGraph.Stats s = app.graph().stats();
            Map<String, Long> byDetector = app.graph().nodes(CodeNodeKind.SINK).stream()
                    .collect(Collectors.groupingBy(n -> n.prop("detector") == null ? "code" : n.prop("detector"),
                            LinkedHashMap::new, Collectors.counting()));
            int pairs = app.graph().sinkPaths(12, 1000).size();
            StringBuilder sb = new StringBuilder();
            sb.append("앱 id: ").append(app.id()).append('\n')
                    .append("대상: ").append(app.origin()).append('\n');
            if (app.android().detected()) {
                sb.append("플랫폼: Android · 매니페스트 ").append(app.android().manifests().size()).append("개 (")
                        .append(app.android().manifests().stream().map(m -> m.path() + (m.namespace().isEmpty() ? "" : " · " + m.namespace()))
                                .collect(Collectors.joining(", "))).append(")\n");
            }
            if (app.ios().detected()) {
                sb.append("플랫폼: iOS · Info.plist ").append(app.ios().infoPlists().size()).append("개, entitlements ")
                        .append(app.ios().entitlements().size()).append("개 (Swift·Objective-C 호출 경로까지)\n");
            }
            if (!app.android().detected() && !app.ios().detected()) {
                sb.append("플랫폼: AndroidManifest.xml·Info.plist 를 찾지 못함 (줄 단위 규칙과 Java·Kotlin 코드만 봄)\n");
            }
            sb.append("파일 ").append(s.files()).append(" · 클래스 ").append(s.classes()).append(" · 메서드 ").append(s.methods())
                    .append(" · 진입점(외부에 열린 컴포넌트·JS 브리지) ").append(s.entryPoints()).append('\n')
                    .append("위험 지점 ").append(s.sinks()).append(" (코드 그래프 ").append(byDetector.getOrDefault("code", 0L))
                    .append(" · 줄 단위 규칙 ").append(byDetector.getOrDefault(StaticSink.LINE, 0L))
                    .append(" · 설정 검사 ").append(byDetector.getOrDefault(StaticSink.CONFIG, 0L)).append(")\n")
                    .append("입구 → 위험 지점 경로(쌍) ").append(pairs).append("개. list_components, list_sink_paths, check_config, list_sinks 로 볼 수 있음\n");
            List<String> errors = new ArrayList<>(s.parseErrors());
            errors.addAll(app.android().errors());
            errors.addAll(app.ios().errors());
            if (!errors.isEmpty()) {
                sb.append("읽지 못한 파일 ").append(errors.size()).append("개: ")
                        .append(String.join("; ", errors.subList(0, Math.min(5, errors.size())))).append('\n');
            }
            List<Finding> existing = findings.list(app.id());
            if (!existing.isEmpty()) {
                sb.append("이전에 기록한 발견 ").append(existing.size()).append("개가 있음 (list_findings). 처음부터 다시 하려면 clear_findings\n");
                long otherCommit = existing.stream()
                        .filter(f -> f.commitSha() != null && app.commitSha() != null && !f.commitSha().equals(app.commitSha()))
                        .count();
                if (otherCommit > 0) {
                    sb.append("그중 ").append(otherCommit).append("개는 다른 커밋에서 기록함. 코드가 바뀌었을 수 있으니 다시 확인할 것\n");
                }
            }
            return sb.toString();
        });
    }

    ToolDef listApps() {
        return new ToolDef("list_apps", "불러온 앱 목록", "이 서버가 불러온 앱 목록.",
                schema(props(), List.of()), true, false, args -> {
            if (registry.all().isEmpty()) {
                return "불러온 앱 없음. load_app 으로 불러올 것";
            }
            return registry.all().stream()
                    .map(a -> a.id() + " · " + a.origin() + " · 위험 지점 " + a.graph().stats().sinks()
                            + " · 발견 " + findings.list(a.id()).size())
                    .collect(Collectors.joining("\n"));
        });
    }

    // ---- 공격 표면 ----

    ToolDef listComponents() {
        return new ToolDef("list_components", "외부에 열린 입구",
                "다른 앱·링크·웹 콘텐츠가 들어올 수 있는 입구 목록: 외부에 열린(exported) Activity·Service·Receiver·Provider 와 "
                        + "딥링크(BROWSABLE), WebView 자바스크립트가 부를 수 있는 @JavascriptInterface 메서드(JS_BRIDGE). "
                        + "권한(permission)이 걸린 것도 보여준다. Java·Kotlin 클래스의 입력을 받는 메서드로 이어진다. '앱 소스에 클래스가 없음' 이면 read_file·grep_code 로 직접 본다.",
                schema(props("app", APP), List.of("app")), true, false, args -> {
            List<Node> entries = app(args).graph().nodes(CodeNodeKind.ENTRY_POINT);
            if (entries.isEmpty()) {
                return "외부에 열린 입구 없음 (매니페스트에 exported 컴포넌트와 @JavascriptInterface 메서드가 없음)";
            }
            return entries.stream().map(SherlockTools::componentLine).collect(Collectors.joining("\n"));
        });
    }

    ToolDef listSinkPaths() {
        return new ToolDef("list_sink_paths", "입구 → 위험 지점 경로",
                "외부에 열린 컴포넌트·JS 브리지에서 위험 지점(SQL, WebView, 파일 경로, Intent, TLS 등)까지 이어지는 호출 경로 (Java 코드). "
                        + "같은 (입구, 위험 지점) 쌍은 가장 짧은 경로 하나만, 위험한 분류부터 돌려준다. 조사할 대상을 고르는 데 쓴다. "
                        + "정적 분석 결과라 틀릴 수 있으니 실제 코드로 확인한다. Kotlin·설정 위험 지점은 경로가 없으니 list_sinks·check_config 로 본다.",
                schema(props(
                        "app", APP,
                        "max_depth", integer("최대 호출 깊이 (기본 12, 최대 30)"),
                        "limit", integer("최대 경로 수 (기본 50, 최대 300)")), List.of("app")),
                true, false, args -> {
            CodeGraph graph = app(args).graph();
            List<SinkPath> paths = graph.sinkPaths(args.integer("max_depth", 12, 1, 30), args.integer("limit", 50, 1, 300));
            if (paths.isEmpty()) {
                return "입구에서 위험 지점까지 가는 경로가 없음";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < paths.size(); i++) {
                SinkPath p = paths.get(i);
                sb.append(i + 1).append(". ").append(p.entryPoint().qualifiedName()).append("  →  ")
                        .append(sinkLabel(p.sink())).append('\n');
                sb.append("   경로: ").append(p.path().stream()
                        .filter(n -> n.kind() == CodeNodeKind.METHOD)
                        .map(n -> shortName(n.qualifiedName()) + "(#" + n.id() + ")")
                        .collect(Collectors.joining(" › "))).append('\n');
                sb.append("   위험 지점 위치: ").append(location(p.sink())).append(" · 코드: ").append(p.sink().prop("snippet")).append('\n');
            }
            return sb.toString();
        });
    }

    ToolDef listSinks() {
        return new ToolDef("list_sinks", "위험 지점 목록",
                "위험 지점 전체. 분류: COMMAND, CODE_LOADING(동적 코드 로딩), SQL, DESERIALIZATION, WEBVIEW(JS 브리지, 파일 URL 접근, "
                        + "신뢰할 수 없는 URL 로드), TLS(인증서·호스트 검증 끄기), INTENT(Intent 리다이렉션, PendingIntent), EXPORTED(권한 없이 열린 컴포넌트), "
                        + "PATH, XXE, CLEARTEXT(평문 HTTP), HARDCODED_SECRET(값은 가림), STORAGE(SharedPreferences·외부 저장소), LOGGING, "
                        + "DEBUGGABLE, BACKUP, WEAK_CRYPTO, WEAK_RANDOM. "
                        + "detector: code(Java 호출, 경로를 알 수 있음), line(줄 단위 규칙, Kotlin 등. 후보일 뿐), config(매니페스트·네트워크 보안 설정). "
                        + "입구에서 닿지 않는 위험 지점도 포함한다.",
                schema(props(
                        "app", APP,
                        "category", string("분류로 거르기 (예: WEBVIEW)"),
                        "detector", enumOf("찾은 방법으로 거르기", DETECTORS)), List.of("app")),
                true, false, args -> {
            String category = args.optionalString("category").map(c -> c.toUpperCase(Locale.ROOT)).orElse(null);
            String detector = args.optionalOneOf("detector", Set.copyOf(DETECTORS)).orElse(null);
            List<Node> sinks = app(args).graph().nodes(CodeNodeKind.SINK).stream()
                    .filter(n -> category == null || category.equals(n.prop("category")))
                    .filter(n -> detector == null || detector.equals(n.prop("detector")))
                    .toList();
            return sinks.isEmpty() ? "위험 지점 없음" : sinks.stream()
                    .map(n -> "#" + n.id() + " " + detectorTag(n) + sinkLabel(n) + " · " + shortName(n.prop("method")) + " · " + location(n)
                            + "\n    " + n.prop("snippet"))
                    .collect(Collectors.joining("\n"));
        });
    }

    ToolDef checkConfig() {
        return new ToolDef("check_config", "설정 검사",
                "AndroidManifest.xml 과 네트워크 보안 설정(res/xml)의 보안 설정: debuggable, allowBackup, usesCleartextTraffic, "
                        + "networkSecurityConfig, 권한 없이 외부에 열린 컴포넌트, 평문 HTTP·사용자 인증서를 허용하는 도메인. "
                        + "debug-overrides 와 src/debug 매니페스트는 배포 앱이 아니므로 보지 않는다. "
                        + "빌드 타입별 설정(build.gradle 의 debuggable, manifestPlaceholders)이 덮어쓸 수 있으니 필요하면 grep_code 로 확인한다.",
                schema(props("app", APP), List.of("app")), true, false, args -> {
            LoadedApp app = app(args);
            if (!app.android().detected() && !app.ios().detected()) {
                return "AndroidManifest.xml·Info.plist 를 찾지 못함";
            }
            StringBuilder sb = new StringBuilder();
            for (var plist : app.ios().infoPlists()) {
                var root = plist.root();
                sb.append("## ").append(plist.path()).append(" (iOS)\n");
                sb.append("- NSAppTransportSecurity = ").append(root.containsKey("NSAppTransportSecurity") ? "있음 (예외 설정)" : "(없음, 기본값: HTTPS 만)").append('\n');
                sb.append("- UIFileSharingEnabled = ").append(root.containsKey("UIFileSharingEnabled") ? root.get("UIFileSharingEnabled").value().name() : "(없음)").append('\n');
                sb.append("- URL 스킴 = ").append(root.containsKey("CFBundleURLTypes") ? "있음 (list_components)" : "(없음)").append('\n');
            }
            for (var plist : app.ios().entitlements()) {
                var root = plist.root();
                sb.append("## ").append(plist.path()).append(" (iOS entitlements)\n");
                sb.append("- get-task-allow = ").append(root.containsKey("get-task-allow") ? root.get("get-task-allow").value().name() : "(없음)").append('\n');
                sb.append("- associated-domains = ").append(root.containsKey("com.apple.developer.associated-domains") ? "있음 (list_components)" : "(없음)").append('\n');
            }
            for (Manifest m : app.android().manifests()) {
                sb.append("## ").append(m.path()).append(m.namespace().isEmpty() ? "" : " (" + m.namespace() + ")").append('\n');
                for (String attr : List.of("android:debuggable", "android:allowBackup", "android:usesCleartextTraffic",
                        "android:networkSecurityConfig", "android:fullBackupContent", "android:dataExtractionRules")) {
                    sb.append("- ").append(attr).append(" = ").append(m.appAttr(attr).orElse("(없음)")).append('\n');
                }
                long exported = m.components().stream().filter(c -> c.exported()).count();
                sb.append("- 컴포넌트 ").append(m.components().size()).append("개 중 외부에 열린 것 ").append(exported).append("개 (list_components)\n");
            }
            List<Node> config = app.graph().nodes(CodeNodeKind.SINK).stream()
                    .filter(n -> StaticSink.CONFIG.equals(n.prop("detector")))
                    .toList();
            sb.append("\n설정 문제 ").append(config.size()).append("개").append(config.isEmpty() ? "" : ":").append('\n');
            config.forEach(n -> sb.append("#").append(n.id()).append(" ").append(sinkLabel(n)).append(" · ").append(location(n))
                    .append(" · ").append(MobileMapping.brief(n.prop("cwe"))).append("\n    ").append(n.prop("snippet")).append('\n'));
            List<String> unread = new ArrayList<>(app.android().errors());
            unread.addAll(app.ios().errors());
            if (!unread.isEmpty()) {
                sb.append("\n읽지 못한 파일: ").append(String.join("; ", unread)).append('\n');
            }
            return sb.toString();
        });
    }

    ToolDef checkDependencies() {
        return new ToolDef("check_dependencies", "라이브러리 취약점",
                "build.gradle(.kts)·gradle/libs.versions.toml·gradle.lockfile, React Native 등의 package-lock.json·yarn.lock·pnpm-lock.yaml 에서 "
                        + "라이브러리와 버전을 읽고, 공개 취약점 DB(OSV, https://osv.dev)에 알려진 취약점(CVE·GHSA, 심각도, 고친 버전)이 있는 것을 보여준다 "
                        + "(OWASP Mobile M2). OSV 에는 라이브러리 좌표와 버전만 보내고 소스코드는 보내지 않는다. "
                        + "검사할 때마다 기록을 남기고 지난 검사와 비교해 바뀐 버전·새 취약점·해결된 취약점을 알려준다. "
                        + "취약한 라이브러리가 있으면 그 기능을 앱이 실제로 쓰는지 read_file·grep_code 로 확인한다.",
                schema(props("app", APP), List.of("app")), false, true,
                args -> {
                    LoadedApp app = app(args);
                    return DependencyService.summarize(dependencies.scan(app.id(), app.root(), app.commitSha()));
                });
    }

    ToolDef findCodeNodes() {
        return new ToolDef("find_code_nodes", "코드 노드 찾기",
                "이름으로 클래스·메서드(Java·Kotlin·Swift·Objective-C)·입구·위험 지점을 찾는다 (대소문자 무시, 부분 일치). 메서드 이름은 'Class#method(ParamType)' 형식이다.",
                schema(props(
                        "app", APP,
                        "query", string("찾을 이름 일부 (예: StatementProvider#query)"),
                        "kind", enumOf("노드 종류로 거르기", List.of("CLASS", "METHOD", "ENTRY_POINT", "SINK"))),
                        List.of("app", "query")),
                true, false, args -> {
            CodeNodeKind kind = args.optionalString("kind").map(k -> CodeNodeKind.valueOf(k.toUpperCase(Locale.ROOT))).orElse(null);
            List<Node> found = app(args).graph().find(args.string("query"), kind).stream()
                    .filter(n -> n.kind() != CodeNodeKind.FILE)
                    .limit(30)
                    .toList();
            return found.isEmpty() ? "찾지 못함" : found.stream().map(SherlockTools::nodeLine).collect(Collectors.joining("\n"));
        });
    }

    ToolDef getCallers() {
        return new ToolDef("get_callers", "호출하는 쪽",
                "이 메서드를 호출하는 메서드와 입구. 부모 클래스·인터페이스 메서드를 통한 호출도 포함한다.",
                schema(props("app", APP, "node", string("노드 번호(예: 12) 또는 이름 (예: StatementProvider#query)")),
                        List.of("app", "node")),
                true, false, args -> {
            CodeGraph graph = app(args).graph();
            Node node = resolveNode(graph, args.string("node"));
            List<Node> callers = graph.callers(node.id());
            return nodeLine(node) + "\n를 호출하는 쪽:\n"
                    + (callers.isEmpty() ? "  (없음)" : callers.stream().map(n -> "  " + nodeLine(n)).collect(Collectors.joining("\n")));
        });
    }

    ToolDef getCallees() {
        return new ToolDef("get_callees", "호출되는 쪽",
                "이 메서드가 호출하는 프로젝트 메서드와 위험 지점. 라이브러리 호출 중 위험 지점이 아닌 것은 나오지 않는다.",
                schema(props("app", APP, "node", string("노드 번호 또는 이름")), List.of("app", "node")),
                true, false, args -> {
            CodeGraph graph = app(args).graph();
            Node node = resolveNode(graph, args.string("node"));
            List<Node> callees = graph.callees(node.id());
            return nodeLine(node) + "\n가 호출하는 쪽:\n"
                    + (callees.isEmpty() ? "  (없음)" : callees.stream().map(n -> "  " + nodeLine(n)).collect(Collectors.joining("\n")));
        });
    }

    // ---- 파일 ----

    ToolDef readFile() {
        return new ToolDef("read_file", "파일 읽기",
                "앱 폴더의 파일을 줄 번호와 함께 읽는다 (Java, Kotlin, XML, gradle 등). 한 번에 최대 400줄. 판단은 반드시 실제 코드를 읽고 한다.",
                schema(props(
                        "app", APP,
                        "path", string("앱 폴더 기준 경로 (예: app/src/main/AndroidManifest.xml)"),
                        "start_line", integer("시작 줄 (기본 1)"),
                        "end_line", integer("끝 줄 (기본 시작 줄 + 199)")), List.of("app", "path")),
                true, false, args -> {
            int start = args.integer("start_line", 1, 1, Integer.MAX_VALUE);
            int end = args.integer("end_line", start + 199, start, Integer.MAX_VALUE);
            return RepoFiles.read(app(args).root(), args.string("path"), start, end);
        });
    }

    ToolDef grepCode() {
        return new ToolDef("grep_code", "코드 검색",
                "정규식(Java 문법)과 일치하는 줄을 '경로:줄: 내용' 으로 찾는다. 최대 80개. 입력 검증, 권한 확인(checkCallingPermission, "
                        + "getCallingPackage), 서명 권한, Intent 의 출처 확인, URL 허용 목록 같은 방어 장치를 찾는 데 쓴다.",
                schema(props(
                        "app", APP,
                        "pattern", string("Java 정규식 (예: checkCallingPermission|getCallingPackage|protectionLevel)"),
                        "file_glob", string("대상 파일 glob, 앱 폴더 기준 (기본 **.{java,kt}, 예: **.xml, **/build.gradle*)")),
                        List.of("app", "pattern")),
                true, false, args -> RepoFiles.grep(app(args).root(), args.string("pattern"),
                args.optionalString("file_glob").orElse("**.{java,kt}")));
    }

    // ---- 발견 ----

    ToolDef recordFinding() {
        Map<String, Object> evidenceItem = Map.of("type", "object",
                "properties", Map.of(
                        "file", string("앱 폴더 기준 파일 경로"),
                        "line", integer("줄 번호"),
                        "note", string("이 줄이 왜 근거인지")),
                "required", List.of("file", "line", "note"));
        return new ToolDef("record_finding", "발견 기록",
                "공격 가능한 취약점을 발견으로 기록한다 (검증 대기 상태). 공격자(다른 앱, 링크, 네트워크, 폰을 가진 사람)가 막힘 없이 "
                        + "위험 지점에 닿는 것, 또는 배포되는 코드·설정 자체의 약점을 직접 확인했을 때만 쓴다. 막는 장치가 있거나 확신이 없으면 기록하지 않는다. 약점 하나(위치 하나 + CWE 하나)에 발견 하나: 열린 컴포넌트(CWE-926)와 그 뒤의 코드 버그, 하드코딩된 키와 약한 암호는 따로 기록한다. "
                        + "기록한 발견은 submit_verdict 로 따로 검증한다. 비밀값은 설명·근거에 그대로 적지 말고 가린다.",
                schema(props(
                        "app", APP,
                        "title", string("취약점 제목 (예: 명세서 Provider 의 SQL 인젝션)"),
                        "cwe", string("CWE 번호 (예: CWE-89)"),
                        "severity", enumOf("심각도", SEVERITIES),
                        "confidence", enumOf("공격 가능하다는 확신", CONFIDENCES),
                        "attacker", enumOf("누가 공격하나: other_app(기기의 다른 앱), link(딥링크·웹 콘텐츠), network(같은 네트워크), "
                                + "device(잃어버리거나 루팅된 폰, APK 를 받은 누구나)", Finding.ATTACKERS),
                        "description", string("입력이 어디서 들어와 어떤 경로로 위험 지점에 닿는지"),
                        "exploit_scenario", string("구체적인 공격 예시 (예: adb shell content query --uri ... --where \"1=1) --\")"),
                        "evidence", Map.of("type", "array", "items", evidenceItem, "description", "근거 코드 위치 (1개 이상)"),
                        "entry_point", string("입구 (예: PROVIDER com.example.bank.data.StatementProvider)"),
                        "sink", string("위험 지점 API (예: SQLiteDatabase.rawQuery)")),
                        List.of("app", "title", "cwe", "severity", "confidence", "attacker", "description", "evidence")),
                false, false, args -> {
            LoadedApp app = app(args);
            List<Evidence> evidence = new ArrayList<>();
            for (Map<String, Object> e : args.objectList("evidence")) {
                Args item = new Args(e);
                String file = item.string("file");
                RepoFiles.resolve(app.root(), file); // 앱 폴더 안 경로인지 확인
                evidence.add(new Evidence(file.replace('\\', '/'), item.integer("line", 1, 1, Integer.MAX_VALUE), item.string("note")));
            }
            if (evidence.isEmpty()) {
                throw new ToolException("evidence 에 근거 코드 위치가 하나 이상 있어야 함");
            }
            String cwe = args.string("cwe").toUpperCase(Locale.ROOT);
            Finding finding = findings.add(app.id(), new Finding(null, args.string("title"), cwe,
                    args.oneOf("severity", Set.copyOf(SEVERITIES)), args.oneOf("confidence", Set.copyOf(CONFIDENCES)),
                    args.string("description"), args.optionalString("exploit_scenario").orElse(null), evidence,
                    args.optionalString("entry_point").orElse(null), args.optionalString("sink").orElse(null),
                    args.oneOf("attacker", Set.copyOf(Finding.ATTACKERS)),
                    Status.OPEN, null, null, app.commitSha()));
            return "발견 " + finding.id() + " 기록함 (검증 대기, " + MobileMapping.brief(cwe) + "). "
                    + "조사를 마친 뒤 반대 입장에서 다시 확인하고 submit_verdict 로 판정할 것";
        });
    }

    ToolDef submitVerdict() {
        return new ToolDef("submit_verdict", "발견 판정",
                "발견을 다시 검증한 결과를 기록한다. 보고서를 그대로 믿지 말고 코드·매니페스트를 직접 다시 읽은 뒤 판정한다. "
                        + "confirmed: 그 공격자가 실제로 공격 가능함을 확인. rejected: 컴포넌트가 열려 있지 않음, 서명 권한, 입력이 공격자에게서 오지 않음, "
                        + "디버그 빌드에만 있음 등으로 막힘(오탐). uncertain: 판단에 필요한 코드가 앱 소스에 없는 등 근거 부족.",
                schema(props(
                        "app", APP,
                        "finding_id", string("발견 id (예: F1)"),
                        "verdict", enumOf("판정", List.of("confirmed", "rejected", "uncertain")),
                        "reasoning", string("판정 근거 (파일:줄 포함)"),
                        "blocking_controls", string("확인한 방어 장치와 그것이 공격을 막는지"),
                        "severity", enumOf("검증 후 다시 매긴 심각도 (바꿀 때만)", SEVERITIES)),
                        List.of("app", "finding_id", "verdict", "reasoning")),
                false, false, args -> {
            Status status = VERDICTS.get(args.oneOf("verdict", VERDICTS.keySet()));
            Finding f = findings.verdict(app(args).id(), args.string("finding_id"), status, args.string("reasoning"),
                    args.optionalString("blocking_controls").orElse(null),
                    args.optionalOneOf("severity", Set.copyOf(SEVERITIES)).orElse(null));
            return f.id() + " 판정 기록함: " + Reports.label(f.status()) + " (심각도 " + f.effectiveSeverity() + ")";
        });
    }

    ToolDef listFindings() {
        return new ToolDef("list_findings", "발견 목록",
                "기록한 발견 목록. 확정 → 검증 대기 → 판단 불가 → 기각 순, 같은 판정 안에서는 심각도 순.",
                schema(props(
                        "app", APP,
                        "status", enumOf("판정으로 거르기", List.of("OPEN", "CONFIRMED", "REJECTED", "UNCERTAIN")),
                        "detail", Map.of("type", "boolean", "description", "설명·근거·검증 내용까지 보여줄지 (기본 false)")),
                        List.of("app")),
                true, false, args -> {
            LoadedApp app = app(args);
            String status = args.optionalString("status").map(s -> s.toUpperCase(Locale.ROOT)).orElse(null);
            List<Finding> list = Reports.sorted(findings.list(app.id())).stream()
                    .filter(f -> status == null || f.status().name().equals(status))
                    .toList();
            if (list.isEmpty()) {
                return "발견 없음";
            }
            if (Boolean.parseBoolean(args.optionalString("detail").orElse("false"))) {
                return Reports.markdown(app, list, true);
            }
            return list.stream()
                    .map(f -> f.id() + " [" + Reports.label(f.status()) + "] " + f.effectiveSeverity() + " " + f.cwe()
                            + " (" + MobileMapping.brief(f.cwe()) + ") " + f.title()
                            + (f.entryPoint() == null ? "" : " · " + f.entryPoint()))
                    .collect(Collectors.joining("\n"));
        });
    }

    ToolDef exportReport() {
        return new ToolDef("export_report", "보고서 내보내기",
                "발견을 보고서 파일로 저장하고 경로를 돌려준다. 발견마다 CWE, OWASP Mobile Top 10, MASVS, 공격자를 적는다. "
                        + "markdown 은 내용도 함께 돌려준다. sarif 는 GitHub 코드 스캐닝 등에 올릴 수 있는 SARIF 2.1.0 (기각된 발견 제외).",
                schema(props(
                        "app", APP,
                        "format", enumOf("형식 (기본 markdown)", List.of("markdown", "sarif")),
                        "include_rejected", Map.of("type", "boolean", "description", "markdown 에 기각된 발견도 넣을지 (기본 false)")),
                        List.of("app")),
                false, false, args -> {
            LoadedApp app = app(args);
            String format = args.optionalOneOf("format", Set.of("markdown", "sarif")).orElse("markdown");
            List<Finding> list = findings.list(app.id());
            String content = format.equals("sarif")
                    ? Reports.sarif(app, list)
                    : Reports.markdown(app, list, Boolean.parseBoolean(args.optionalString("include_rejected").orElse("false")));
            String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            Path file = workspace.reports().resolve(app.id() + "-" + stamp + (format.equals("sarif") ? ".sarif" : ".md"));
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, content, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return "저장함: " + file.toAbsolutePath() + (format.equals("sarif") ? "" : "\n\n" + content);
        });
    }

    ToolDef clearFindings() {
        return new ToolDef("clear_findings", "발견 모두 지우기",
                "이 앱의 발견을 모두 지운다. 처음부터 다시 분석할 때만, 사용자가 원할 때 쓴다.",
                schema(props("app", APP), List.of("app")), false, false,
                args -> "발견 " + findings.clear(app(args).id()) + "개를 지움");
    }

    // ---- 헬퍼 ----

    private LoadedApp app(Args args) {
        return registry.get(args.string("app"));
    }

    static Node resolveNode(CodeGraph graph, String ref) {
        String r = ref.strip().replaceFirst("^#", "");
        if (r.matches("\\d+")) {
            return graph.node(Integer.parseInt(r)).orElseThrow(() -> new ToolException("노드 없음: #" + r));
        }
        List<Node> found = graph.find(r, null).stream()
                .filter(n -> n.kind() == CodeNodeKind.METHOD || n.kind() == CodeNodeKind.ENTRY_POINT || n.kind() == CodeNodeKind.SINK)
                .toList();
        if (found.isEmpty()) {
            throw new ToolException("찾지 못함: " + ref + ". find_code_nodes 로 이름을 확인할 것");
        }
        List<Node> exact = found.stream().filter(n -> shortName(n.qualifiedName()).toLowerCase(Locale.ROOT)
                .startsWith(r.toLowerCase(Locale.ROOT)) || n.qualifiedName().equalsIgnoreCase(r)).toList();
        List<Node> candidates = exact.isEmpty() ? found : exact;
        List<Node> methods = candidates.stream().filter(n -> n.kind() == CodeNodeKind.METHOD).toList();
        if (methods.size() == 1) {
            return methods.get(0);
        }
        if (candidates.size() > 1 && !candidates.get(0).qualifiedName().equalsIgnoreCase(r)) {
            throw new ToolException("여러 개가 일치함. 번호로 다시 지정할 것:\n" + candidates.stream().limit(10)
                    .map(SherlockTools::nodeLine).collect(Collectors.joining("\n")));
        }
        return candidates.get(0);
    }

    static String nodeLine(Node n) {
        String name = switch (n.kind()) {
            case ENTRY_POINT -> n.qualifiedName();
            case SINK -> sinkLabel(n) + " (" + n.prop("method") + ")";
            default -> n.qualifiedName();
        };
        String loc = location(n);
        return "#" + n.id() + " " + n.kind() + " " + name + (loc.isEmpty() ? "" : "  [" + loc + "]");
    }

    /** 입구 한 줄: 종류, 클래스, 열린 방식, 권한, 딥링크·액션, 입력을 받는 메서드 */
    @SuppressWarnings("unchecked")
    static String componentLine(Node n) {
        StringBuilder sb = new StringBuilder("#").append(n.id()).append(' ').append(n.qualifiedName());
        if (n.props().get("launcher") != null) {
            sb.append(" [런처]");
        }
        if ("implicit".equals(n.prop("exported"))) {
            sb.append(" [exported 를 적지 않았지만 인텐트 필터로 열림]");
        }
        String permission = n.prop("permission") != null ? n.prop("permission")
                : n.prop("readPermission") != null || n.prop("writePermission") != null
                ? "read=" + n.prop("readPermission") + ", write=" + n.prop("writePermission") : null;
        sb.append(permission == null ? (n.prop("kind").equals("JS_BRIDGE") ? "" : " · 권한 없음") : " · 권한 " + permission);
        Object deepLinks = n.props().get("deepLinks");
        if (deepLinks instanceof List<?> links && !links.isEmpty()) {
            sb.append(" · 딥링크 ").append(String.join(", ", (List<String>) links));
        }
        Object actions = n.props().get("actions");
        if (actions instanceof List<?> list && !list.isEmpty()) {
            sb.append(" · 액션 ").append(String.join(", ", (List<String>) list));
        }
        if (n.prop("authorities") != null) {
            sb.append(" · authorities ").append(n.prop("authorities"));
        }
        Object handlers = n.props().get("handlers");
        if (handlers instanceof List<?> list && !list.isEmpty()) {
            sb.append("\n    입력을 받는 메서드: ").append(((List<String>) list).stream().map(SherlockTools::shortName)
                    .collect(Collectors.joining(", ")));
        } else if (n.prop("source") != null) {
            sb.append("\n    ").append(n.prop("source"));
        }
        sb.append("\n    위치: ").append(location(n));
        if (n.prop("declaredIn") != null) {
            sb.append(" · 선언: ").append(n.prop("declaredIn"));
        }
        return sb.toString();
    }

    static String sinkLabel(Node n) {
        return "[" + n.prop("category") + " " + n.prop("cwe") + "] " + n.prop("api");
    }

    private static String detectorTag(Node n) {
        return switch (String.valueOf(n.prop("detector"))) {
            case StaticSink.LINE -> "[줄 규칙] ";
            case StaticSink.CONFIG -> "[설정] ";
            default -> "";
        };
    }

    static String location(Node n) {
        if (n.filePath() == null) {
            return "";
        }
        return n.line() == null ? n.filePath() : n.filePath() + ":" + n.line();
    }

    /** com.example.Foo#bar(String) → Foo#bar(String) */
    static String shortName(String qualifiedName) {
        if (qualifiedName == null) {
            return "";
        }
        int hash = qualifiedName.indexOf('#');
        if (hash < 0 && qualifiedName.matches(".+\\.[a-z]{1,10}$")) {
            return qualifiedName; // 파일 이름 (예: SearchRepository.kt)
        }
        String owner = hash < 0 ? qualifiedName : qualifiedName.substring(0, hash);
        String simple = owner.substring(owner.lastIndexOf('.') + 1);
        return hash < 0 ? simple : simple + qualifiedName.substring(hash);
    }

    /** 순서를 지키는 properties 맵 (이름, 스키마, 이름, 스키마, ...) */
    @SuppressWarnings("unchecked")
    static Map<String, Map<String, Object>> props(Object... pairs) {
        Map<String, Map<String, Object>> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], (Map<String, Object>) pairs[i + 1]);
        }
        return map;
    }
}
