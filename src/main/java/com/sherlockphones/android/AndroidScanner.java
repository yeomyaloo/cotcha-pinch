package com.sherlockphones.android;

import com.codeagent.core.kotlin.KotlinProject;
import com.sherlockphones.android.AndroidManifests.Declared;
import com.sherlockphones.android.AndroidManifests.Manifest;
import com.sherlockphones.codegraph.AppScan;
import com.sherlockphones.codegraph.Component;
import com.sherlockphones.codegraph.LineRule;
import com.sherlockphones.codegraph.LineScanner;
import com.sherlockphones.codegraph.StaticSink;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 안드로이드 앱을 훑어 코드 그래프 재료(외부에 열린 컴포넌트, 설정·줄 단위 위험 지점, Java 규칙)를 만든다.
 */
public final class AndroidScanner {

    /**
     * @param manifests 읽은 매니페스트 (모듈마다 하나)
     * @param errors    읽지 못한 설정 파일
     */
    public record AndroidApp(List<Manifest> manifests, List<String> errors, AppScan scan) {

        public boolean detected() {
            return !manifests.isEmpty();
        }
    }

    private AndroidScanner() {
    }

    public static AndroidApp scan(Path root) {
        List<String> errors = new ArrayList<>();
        List<Manifest> manifests = AndroidManifests.load(root, errors);
        List<Component> components = new ArrayList<>();
        List<StaticSink> sinks = new ArrayList<>();
        for (Manifest manifest : manifests) {
            for (Declared declared : manifest.components()) {
                if (declared.exported()) {
                    components.add(component(manifest, declared));
                }
            }
            sinks.addAll(AndroidConfigChecks.check(root, manifest, errors));
        }
        // Kotlin 파서를 쓸 수 있으면 Kotlin 호출은 코드 그래프가 찾는다. 못 쓰는 OS/CPU 에서만 줄 단위로 흉내 낸다
        List<LineRule> rules = new ArrayList<>(AndroidRules.LINE_RULES);
        if (!KotlinProject.available()) {
            rules.addAll(AndroidRules.KOTLIN_CALL_FALLBACK);
        }
        sinks.addAll(LineScanner.scan(root, rules));
        AppScan scan = new AppScan(List.copyOf(components), List.copyOf(sinks), AndroidRules.JAVA_RULES,
                AndroidRules.KNOWN_RETURN_TYPES, AndroidRules.BRIDGE_ANNOTATIONS);
        return new AndroidApp(List.copyOf(manifests), List.copyOf(errors), scan);
    }

    private static Component component(Manifest manifest, Declared declared) {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("exported", declared.implicitlyExported() ? "implicit" : "true");
        if (declared.permission() != null) {
            props.put("permission", declared.permission());
        }
        if (declared.readPermission() != null) {
            props.put("readPermission", declared.readPermission());
        }
        if (declared.writePermission() != null) {
            props.put("writePermission", declared.writePermission());
        }
        if (!declared.actions().isEmpty()) {
            props.put("actions", declared.actions());
        }
        if (!declared.deepLinks().isEmpty()) {
            props.put("deepLinks", declared.deepLinks());
        }
        if (declared.authorities() != null) {
            props.put("authorities", declared.authorities());
        }
        if (declared.launcher()) {
            props.put("launcher", true);
        }
        return new Component(declared.kind(), declared.className(),
                AndroidRules.HANDLERS.getOrDefault(declared.kind(), List.of()), manifest.path(), declared.element().line(), props);
    }
}
