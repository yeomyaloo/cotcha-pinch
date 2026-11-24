package com.sherlockphones.android;

import com.sherlockphones.android.XmlTree.Document;
import com.sherlockphones.android.XmlTree.Element;
import com.sherlockphones.codegraph.LineScanner;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * 앱 폴더에서 AndroidManifest.xml 을 찾아 읽는다. 모듈마다 src/main/AndroidManifest.xml 을 쓰고,
 * 디버그·테스트용 매니페스트(src/debug, src/androidTest)는 배포되는 앱이 아니므로 보지 않는다.
 */
public final class AndroidManifests {

    private static final Pattern NAMESPACE = Pattern.compile("\\bnamespace\\s*=?\\s*[\"']([\\w.]+)[\"']");
    private static final Pattern APPLICATION_ID = Pattern.compile("\\bapplicationId\\s*=?\\s*[\"']([\\w.]+)[\"']");
    private static final List<String> COMPONENT_TAGS = List.of("activity", "activity-alias", "service", "receiver", "provider");

    /**
     * @param path      앱 폴더 기준 매니페스트 경로
     * @param moduleDir 모듈 폴더 (app/ 등). 매니페스트가 루트에 있으면 앱 폴더
     * @param namespace 클래스 이름 앞에 붙는 패키지 (manifest package 또는 build.gradle namespace)
     */
    public record Manifest(String path, Path moduleDir, String namespace, Document document, Element application,
                           List<Declared> components) {

        public Optional<String> appAttr(String name) {
            return application == null ? Optional.empty() : application.attr(name);
        }
    }

    /**
     * 매니페스트에 선언한 컴포넌트 하나.
     *
     * @param kind         ACTIVITY, SERVICE, RECEIVER, PROVIDER
     * @param className    구현 클래스 FQN
     * @param exportedAttr android:exported 값. 적지 않았으면 null
     * @param deepLinks    BROWSABLE 인텐트 필터의 scheme://host/path
     */
    public record Declared(String kind, String className, Element element, Boolean exportedAttr, boolean hasIntentFilter,
                           String permission, String readPermission, String writePermission, List<String> actions,
                           List<String> deepLinks, boolean launcher, boolean browsable, String authorities) {

        /** 다른 앱이 부를 수 있는지. exported 를 적지 않았으면 인텐트 필터가 있을 때 열린다 (Provider 는 닫힘, API 17+) */
        public boolean exported() {
            if (exportedAttr != null) {
                return exportedAttr;
            }
            return !kind.equals("PROVIDER") && hasIntentFilter;
        }

        /** exported 를 적지 않았는데 인텐트 필터 때문에 열린 경우 */
        public boolean implicitlyExported() {
            return exportedAttr == null && exported();
        }

        /** 부르는 앱에 권한을 요구하는지 */
        public boolean permissionProtected() {
            if (kind.equals("PROVIDER")) {
                return permission != null || (readPermission != null && writePermission != null);
            }
            return permission != null;
        }
    }

    private AndroidManifests() {
    }

    /** @param errors 읽지 못한 매니페스트를 여기에 적는다 */
    public static List<Manifest> load(Path root, List<String> errors) {
        List<Path> files = find(root);
        List<Manifest> manifests = new ArrayList<>();
        for (Path file : files) {
            String relative = root.relativize(file).toString().replace('\\', '/');
            try {
                Document document = XmlTree.parse(file);
                if (!document.root().name().equals("manifest")) {
                    continue;
                }
                Path moduleDir = moduleDir(root, file);
                String namespace = document.root().attr("package").orElseGet(() -> gradleNamespace(moduleDir).orElse(""));
                Element application = document.root().children("application").stream().findFirst().orElse(null);
                manifests.add(new Manifest(relative, moduleDir, namespace, document, application,
                        application == null ? List.of() : components(application, namespace)));
            } catch (IOException e) {
                errors.add(relative + ": " + e.getMessage());
            }
        }
        return manifests;
    }

    /** src/main/AndroidManifest.xml 들. 없으면 (예전 구조) 테스트·빌드 폴더가 아닌 곳의 매니페스트 */
    static List<Path> find(Path root) {
        try (Stream<Path> walk = Files.walk(root, 12)) {
            List<Path> all = walk.filter(p -> p.getFileName().toString().equals("AndroidManifest.xml"))
                    .filter(Files::isRegularFile)
                    .filter(p -> !Files.isSymbolicLink(p))
                    .filter(p -> !LineScanner.skipped(root.relativize(p)))
                    .sorted()
                    .toList();
            List<Path> main = all.stream().filter(p -> p.getParent() != null && p.getParent().endsWith(Path.of("src", "main"))).toList();
            if (!main.isEmpty()) {
                return main;
            }
            return all.stream().filter(p -> !p.toString().replace('\\', '/').matches(".*/src/(debug|release|[a-z]+Debug)/.*")).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path moduleDir(Path root, Path manifest) {
        Path parent = manifest.getParent();
        if (parent.endsWith(Path.of("src", "main"))) {
            return parent.getParent().getParent();
        }
        return parent == null ? root : parent;
    }

    private static Optional<String> gradleNamespace(Path moduleDir) {
        for (String name : List.of("build.gradle", "build.gradle.kts")) {
            Path file = moduleDir.resolve(name);
            if (Files.isRegularFile(file)) {
                try {
                    String text = Files.readString(file, StandardCharsets.UTF_8);
                    Matcher m = NAMESPACE.matcher(text);
                    if (m.find()) {
                        return Optional.of(m.group(1));
                    }
                    m = APPLICATION_ID.matcher(text);
                    if (m.find()) {
                        return Optional.of(m.group(1));
                    }
                } catch (IOException e) {
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    private static List<Declared> components(Element application, String namespace) {
        List<Declared> result = new ArrayList<>();
        for (Element element : application.children()) {
            if (!COMPONENT_TAGS.contains(element.name())) {
                continue;
            }
            String name = element.name().equals("activity-alias")
                    ? element.attr("android:targetActivity").orElse(null)
                    : element.attr("android:name").orElse(null);
            if (name == null) {
                continue;
            }
            String kind = element.name().equals("activity-alias") ? "ACTIVITY" : element.name().toUpperCase(Locale.ROOT);
            List<Element> filters = element.children("intent-filter");
            List<String> actions = new ArrayList<>();
            List<String> deepLinks = new ArrayList<>();
            boolean launcher = false;
            boolean browsable = false;
            for (Element filter : filters) {
                List<String> filterActions = filter.children("action").stream().map(a -> a.attr("android:name").orElse("")).toList();
                List<String> categories = filter.children("category").stream().map(c -> c.attr("android:name").orElse("")).toList();
                actions.addAll(filterActions);
                launcher |= filterActions.contains("android.intent.action.MAIN") && categories.contains("android.intent.category.LAUNCHER");
                if (categories.contains("android.intent.category.BROWSABLE")) {
                    browsable = true;
                    deepLinks.addAll(deepLinks(filter));
                }
            }
            Boolean exported = element.attr("android:exported").map(v -> v.equalsIgnoreCase("true")).orElse(null);
            result.add(new Declared(kind, className(name, namespace), element, exported, !filters.isEmpty(),
                    element.attr("android:permission").orElse(null),
                    element.attr("android:readPermission").orElse(null),
                    element.attr("android:writePermission").orElse(null),
                    List.copyOf(actions), List.copyOf(deepLinks), launcher, browsable,
                    element.attr("android:authorities").orElse(null)));
        }
        return result;
    }

    /** data 요소들을 scheme://host/path 로 */
    private static List<String> deepLinks(Element filter) {
        List<String> schemes = new ArrayList<>();
        List<String> hosts = new ArrayList<>();
        List<String> paths = new ArrayList<>();
        for (Element data : filter.children("data")) {
            data.attr("android:scheme").ifPresent(schemes::add);
            data.attr("android:host").ifPresent(hosts::add);
            data.attr("android:path").or(() -> data.attr("android:pathPrefix")).or(() -> data.attr("android:pathPattern"))
                    .ifPresent(paths::add);
        }
        List<String> links = new ArrayList<>();
        for (String scheme : schemes.isEmpty() ? List.of("*") : schemes) {
            for (String host : hosts.isEmpty() ? List.of("*") : hosts) {
                for (String path : paths.isEmpty() ? List.of("") : paths) {
                    links.add(scheme + "://" + host + path);
                }
            }
        }
        return links;
    }

    /** .Main → 패키지.Main, Main → 패키지.Main, 이미 FQN 이면 그대로 */
    static String className(String name, String namespace) {
        if (name.startsWith(".")) {
            return namespace + name;
        }
        if (!name.contains(".") && !namespace.isEmpty()) {
            return namespace + "." + name;
        }
        return name;
    }

    /** 매니페스트 속성 값이 true 인지 */
    static boolean isTrue(Optional<String> value) {
        return value.map(v -> v.equalsIgnoreCase("true")).orElse(false);
    }

    /** @xml/network_security_config → 모듈의 res/xml/network_security_config.xml */
    static Optional<Path> xmlResource(Manifest manifest, String reference) {
        if (reference == null || !reference.startsWith("@xml/")) {
            return Optional.empty();
        }
        Path file = manifest.moduleDir().resolve(Path.of("src", "main", "res", "xml", reference.substring(5) + ".xml"));
        if (!Files.isRegularFile(file)) {
            file = manifest.moduleDir().resolve(Path.of("res", "xml", reference.substring(5) + ".xml"));
        }
        return Files.isRegularFile(file) ? Optional.of(file) : Optional.empty();
    }
}
