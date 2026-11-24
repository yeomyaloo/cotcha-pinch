package com.sherlockphones.ios;

import com.sherlockphones.android.XmlTree;
import com.sherlockphones.codegraph.Component;
import com.sherlockphones.codegraph.LineScanner;
import com.sherlockphones.codegraph.StaticSink;
import com.sherlockphones.ios.Plist.Entry;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * iOS 앱을 훑는다: Info.plist(ATS 예외, 파일 공유, URL 스킴), *.entitlements(디버그 허용, 유니버설 링크),
 * Swift·Objective-C 줄 단위 규칙. URL 스킴·유니버설 링크 입구에는 URL 을 받는 곳(handlerLocations, 파일:줄)을 달고,
 * 코드 그래프가 그 위치의 Swift 함수·Objective-C 메서드로 잇는다.
 */
public final class IosScanner {

    /** Pods·빌드 결과물·테스트 번들은 배포 앱의 소스가 아니다 */
    private static final Set<String> SKIP_DIRS = Set.of(".git", "Pods", "Carthage", "DerivedData", "build", ".build",
            "node_modules", "fastlane", "vendor");
    /** URL 스킴으로 열릴 때 부르는 곳: application(_:open:options:), scene(_:openURLContexts:), onOpenURL, ObjC openURL: */
    private static final Pattern URL_HANDLER = Pattern.compile(
            "func\\s+application\\s*\\([^)]*open\\s+url\\s*:|openURLContexts|\\.onOpenURL\\s*\\{|"
                    + "application:\\s*\\(UIApplication\\s*\\*\\)\\s*\\w+\\s+openURL:");
    /** 유니버설 링크로 열릴 때 부르는 곳: application(_:continue:restorationHandler:), scene(_:continue:), onOpenURL, onContinueUserActivity */
    private static final Pattern LINK_HANDLER = Pattern.compile(
            "continue\\s+userActivity|continueUserActivity:|\\.onOpenURL\\s*\\{|\\.onContinueUserActivity\\s*\\(");

    /**
     * @param infoPlists   Info.plist (테스트·확장 번들 제외)
     * @param entitlements *.entitlements
     */
    public record IosApp(List<Plist> infoPlists, List<Plist> entitlements, List<String> errors, List<Component> components,
                         List<StaticSink> staticSinks) {

        public boolean detected() {
            return !infoPlists.isEmpty() || !entitlements.isEmpty();
        }
    }

    private IosScanner() {
    }

    public static IosApp scan(Path root) {
        List<String> errors = new ArrayList<>();
        List<Plist> infoPlists = new ArrayList<>();
        List<Plist> entitlements = new ArrayList<>();
        for (Path file : find(root)) {
            String relative = root.relativize(file).toString().replace('\\', '/');
            try {
                Plist plist = new Plist(relative, XmlTree.parsePlist(file));
                if (file.getFileName().toString().endsWith(".entitlements")) {
                    entitlements.add(plist);
                } else {
                    infoPlists.add(plist);
                }
            } catch (IOException e) {
                errors.add(relative + ": " + e.getMessage());
            }
        }
        List<StaticSink> sinks = new ArrayList<>();
        List<Component> components = new ArrayList<>();
        List<String> urlHandlers = handlers(root, URL_HANDLER);
        List<String> linkHandlers = handlers(root, LINK_HANDLER);
        infoPlists.forEach(p -> checkInfoPlist(p, sinks, components, urlHandlers));
        entitlements.forEach(p -> checkEntitlements(p, sinks, components, linkHandlers));
        sinks.addAll(LineScanner.scan(root, IosRules.LINE_RULES));
        return new IosApp(List.copyOf(infoPlists), List.copyOf(entitlements), List.copyOf(errors), List.copyOf(components),
                List.copyOf(sinks));
    }

    // ---- Info.plist ----

    static void checkInfoPlist(Plist plist, List<StaticSink> sinks, List<Component> components, List<String> handlers) {
        Map<String, Entry> root = plist.root();
        Plist.dictValue(root.get("NSAppTransportSecurity")).ifPresent(ats -> {
            flagTrue(plist, ats.get("NSAllowsArbitraryLoads"), "CLEARTEXT", "CWE-319",
                    "ATS: NSAllowsArbitraryLoads (모든 도메인에 평문 HTTP 허용)", sinks);
            flagTrue(plist, ats.get("NSAllowsArbitraryLoadsInWebContent"), "CLEARTEXT", "CWE-319",
                    "ATS: NSAllowsArbitraryLoadsInWebContent (WebView 에서 평문 HTTP 허용)", sinks);
            flagTrue(plist, ats.get("NSAllowsArbitraryLoadsForMedia"), "CLEARTEXT", "CWE-319",
                    "ATS: NSAllowsArbitraryLoadsForMedia (미디어에 평문 HTTP 허용)", sinks);
            Plist.dictValue(ats.get("NSExceptionDomains")).ifPresent(domains -> domains.forEach((domain, entry) ->
                    Plist.dictValue(entry).ifPresent(settings -> {
                        for (String key : List.of("NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads")) {
                            flagTrue(plist, settings.get(key), "CLEARTEXT", "CWE-319", "ATS 예외: " + domain + " 에 평문 HTTP 허용", sinks);
                        }
                        for (String key : List.of("NSExceptionMinimumTLSVersion", "NSTemporaryExceptionMinimumTLSVersion")) {
                            Entry tls = settings.get(key);
                            if (tls != null && tls.text().matches("TLSv1\\.[01]")) {
                                sinks.add(sink(plist, tls.line(), "TLS", "CWE-326", "ATS 예외: " + domain + " 에 " + tls.text() + " 허용"));
                            }
                        }
                    })));
        });
        flagTrue(plist, root.get("UIFileSharingEnabled"), "STORAGE", "CWE-922",
                "UIFileSharingEnabled (앱 Documents 폴더를 파일 앱·컴퓨터로 꺼낼 수 있음)", sinks);
        // URL 스킴: 다른 앱·웹 페이지가 bankapp://... 로 앱을 연다
        for (var type : Plist.items(root.get("CFBundleURLTypes"))) {
            if (!type.name().equals("dict")) {
                continue;
            }
            Entry schemes = Plist.dict(type).get("CFBundleURLSchemes");
            for (String scheme : Plist.strings(schemes)) {
                Map<String, Object> props = new LinkedHashMap<>();
                props.put("exported", "true");
                props.put("deepLinks", List.of(scheme + "://"));
                props.put("handlerLocations", handlers);
                props.put("source", handlerNote(handlers));
                components.add(new Component("URL_SCHEME", scheme + "://", List.of(), plist.path(),
                        schemes == null ? type.line() : schemes.line(), props));
            }
        }
    }

    // ---- *.entitlements ----

    static void checkEntitlements(Plist plist, List<StaticSink> sinks, List<Component> components, List<String> handlers) {
        Map<String, Entry> root = plist.root();
        flagTrue(plist, root.get("get-task-allow"), "DEBUGGABLE", "CWE-489",
                "get-task-allow=true (다른 프로세스가 디버거로 붙을 수 있음, 배포 빌드면 문제)", sinks);
        Entry domains = root.get("com.apple.developer.associated-domains");
        for (String domain : Plist.strings(domains)) {
            if (!domain.startsWith("applinks:")) {
                continue;
            }
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("exported", "true");
            props.put("deepLinks", List.of("https://" + domain.substring("applinks:".length()) + "/"));
            props.put("handlerLocations", handlers);
            props.put("source", handlerNote(handlers));
            components.add(new Component("UNIVERSAL_LINK", domain, List.of(), plist.path(), domains.line(), props));
        }
    }

    private static void flagTrue(Plist plist, Entry entry, String category, String cwe, String api, List<StaticSink> sinks) {
        if (entry != null && entry.isTrue()) {
            sinks.add(sink(plist, entry.line(), category, cwe, api));
        }
    }

    private static StaticSink sink(Plist plist, int line, String category, String cwe, String api) {
        List<String> lines = plist.document().lines();
        String snippet = line >= 1 && line <= lines.size() ? LineScanner.snippet(lines.get(line - 1), null) : "";
        return new StaticSink(plist.path(), line, 1, category, cwe, api, snippet, StaticSink.CONFIG);
    }

    /** 함수로 잇지 못했을 때(SwiftUI 클로저, 파서를 쓸 수 없음) 보여 줄 위치 */
    private static String handlerNote(List<String> handlers) {
        return "호출 경로 없음. URL 을 받는 곳: "
                + (handlers.isEmpty() ? "찾지 못함 (grep_code 로 openURL·onOpenURL·userActivity 를 찾을 것)" : String.join(", ", handlers));
    }

    /** 패턴이 걸리는 Swift·Objective-C 파일:줄 */
    static List<String> handlers(Path root, Pattern pattern) {
        List<String> found = new ArrayList<>();
        for (Path file : sources(root)) {
            try {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    Matcher m = pattern.matcher(lines.get(i));
                    if (m.find()) {
                        found.add(root.relativize(file).toString().replace('\\', '/') + ":" + (i + 1));
                    }
                }
            } catch (IOException | UncheckedIOException e) {
                // 읽지 못한 파일은 건너뛴다 (UTF-8 이 아닌 파일 등)
            }
        }
        return found;
    }

    private static List<Path> find(Path root) {
        return walk(root, p -> {
            String name = p.getFileName().toString();
            return name.equals("Info.plist") || name.endsWith(".entitlements");
        });
    }

    private static List<Path> sources(Path root) {
        return walk(root, p -> p.getFileName().toString().matches(".*\\.(swift|m|mm)$"));
    }

    private static List<Path> walk(Path root, java.util.function.Predicate<Path> filter) {
        try (Stream<Path> walk = Files.walk(root, 15)) {
            return walk.filter(Files::isRegularFile)
                    .filter(p -> !Files.isSymbolicLink(p))
                    .filter(p -> !skipped(root.relativize(p)))
                    .filter(filter)
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Pods·빌드 폴더와 테스트 번들(…Tests, …UITests) */
    private static boolean skipped(Path relative) {
        for (int i = 0; i < relative.getNameCount() - 1; i++) {
            String part = relative.getName(i).toString();
            if (SKIP_DIRS.contains(part) || part.endsWith("Tests") || part.endsWith(".xcassets")) {
                return true;
            }
        }
        return LineScanner.skipped(relative);
    }
}
