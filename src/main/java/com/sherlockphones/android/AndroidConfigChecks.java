package com.sherlockphones.android;

import com.sherlockphones.android.AndroidManifests.Declared;
import com.sherlockphones.android.AndroidManifests.Manifest;
import com.sherlockphones.android.XmlTree.Document;
import com.sherlockphones.android.XmlTree.Element;
import com.sherlockphones.codegraph.LineScanner;
import com.sherlockphones.codegraph.StaticSink;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 파서 없이 설정 파일만 보고 찾는 문제: 매니페스트 속성, 권한 없이 열린 컴포넌트, 네트워크 보안 설정.
 * 결과는 설정 위험 지점(detector=config)이 된다.
 */
public final class AndroidConfigChecks {

    private AndroidConfigChecks() {
    }

    public static List<StaticSink> check(Path root, Manifest manifest, List<String> errors) {
        List<StaticSink> sinks = new ArrayList<>();
        Document doc = manifest.document();
        Element app = manifest.application();
        if (app != null) {
            flag(sinks, manifest, app, "android:debuggable", "DEBUGGABLE", "CWE-489",
                    "android:debuggable=\"true\" (배포한 앱에 디버거를 붙일 수 있음)");
            flag(sinks, manifest, app, "android:allowBackup", "BACKUP", "CWE-530",
                    "android:allowBackup=\"true\" (adb 백업으로 앱 데이터를 꺼낼 수 있음)");
            flag(sinks, manifest, app, "android:usesCleartextTraffic", "CLEARTEXT", "CWE-319",
                    "android:usesCleartextTraffic=\"true\" (평문 HTTP 허용)");
        }
        for (Declared c : manifest.components()) {
            if (!c.exported() || c.permissionProtected() || c.launcher() || c.browsable()) {
                continue;
            }
            int line = c.exportedAttr() != null ? doc.lineOf(c.element(), "android:exported") : c.element().line();
            String api = "권한 없이 외부에 열린 " + c.kind() + " " + c.className()
                    + (c.implicitlyExported() ? " (exported 를 적지 않았지만 인텐트 필터 때문에 열림)" : "");
            sinks.add(sink(manifest.path(), line, "EXPORTED", "CWE-926", api, doc));
        }
        if (app != null) {
            Optional<String> nsc = app.attr("android:networkSecurityConfig");
            nsc.flatMap(ref -> AndroidManifests.xmlResource(manifest, ref))
                    .ifPresent(file -> sinks.addAll(networkSecurityConfig(root, file, errors)));
        }
        return sinks;
    }

    /** res/xml/network_security_config.xml. debug-overrides 는 디버그 빌드에만 쓰이므로 보지 않는다 */
    static List<StaticSink> networkSecurityConfig(Path root, Path file, List<String> errors) {
        String relative = root.relativize(file).toString().replace('\\', '/');
        Document doc;
        try {
            doc = XmlTree.parse(file);
        } catch (IOException e) {
            errors.add(relative + ": " + e.getMessage());
            return List.of();
        }
        List<StaticSink> sinks = new ArrayList<>();
        List<Element> configs = new ArrayList<>();
        doc.root().children("base-config").forEach(configs::add);
        for (Element domainConfig : doc.root().children("domain-config")) {
            configs.add(domainConfig);
            configs.addAll(domainConfig.descendants("domain-config"));
        }
        for (Element config : configs) {
            String scope = config.name().equals("base-config") ? "모든 도메인" : domains(config);
            if (AndroidManifests.isTrue(config.attr("cleartextTrafficPermitted"))) {
                sinks.add(sink(relative, doc.lineOf(config, "cleartextTrafficPermitted"), "CLEARTEXT", "CWE-319",
                        "network_security_config: 평문 HTTP 허용 (" + scope + ")", doc));
            }
            for (Element anchors : config.children("trust-anchors")) {
                for (Element certificates : anchors.children("certificates")) {
                    if ("user".equals(certificates.attr("src").orElse(""))) {
                        sinks.add(sink(relative, certificates.line(), "TLS", "CWE-295",
                                "network_security_config: 사용자가 설치한 인증서도 신뢰 (" + scope + ")", doc));
                    }
                }
            }
        }
        return sinks;
    }

    private static void flag(List<StaticSink> sinks, Manifest manifest, Element app, String attribute, String category,
                             String cwe, String api) {
        if (AndroidManifests.isTrue(app.attr(attribute))) {
            sinks.add(sink(manifest.path(), manifest.document().lineOf(app, attribute), category, cwe, api, manifest.document()));
        }
    }

    private static String domains(Element config) {
        String names = config.children("domain").stream()
                .map(d -> d.attrs().getOrDefault("includeSubdomains", "false").equals("true") ? "*." + text(d) : text(d))
                .collect(Collectors.joining(", "));
        return names.isEmpty() ? "도메인 설정" : names;
    }

    /** 요소 안의 글자 (XmlTree 가 #text 로 둔다) */
    private static String text(Element domain) {
        return domain.attrs().getOrDefault("#text", "?");
    }

    private static StaticSink sink(String file, int line, String category, String cwe, String api, Document doc) {
        String snippet = line >= 1 && line <= doc.lines().size() ? LineScanner.snippet(doc.lines().get(line - 1), null) : "";
        return new StaticSink(file, line, 1, category, cwe, api, snippet, StaticSink.CONFIG);
    }
}
