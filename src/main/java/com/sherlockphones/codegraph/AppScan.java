package com.sherlockphones.codegraph;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 플랫폼(안드로이드, 나중에 iOS)이 코드 그래프를 만들 때 넘기는 재료.
 *
 * @param components        외부에 열린 입구 (진입점이 된다)
 * @param staticSinks       줄 단위 규칙·설정 파일 검사로 찾은 위험 지점
 * @param sinkRules         Java 호출 위험 지점 규칙
 * @param knownReturnTypes  라이브러리 jar 없이 반환 타입을 알 수 있는 메서드 (예: getIntent → android.content.Intent)
 * @param bridgeAnnotations 웹 콘텐츠가 부를 수 있는 메서드에 붙는 애너테이션 (예: android.webkit.JavascriptInterface)
 */
public record AppScan(List<Component> components, List<StaticSink> staticSinks, List<SinkRule> sinkRules,
                      Map<String, String> knownReturnTypes, Set<String> bridgeAnnotations) {

    public static AppScan empty() {
        return new AppScan(List.of(), List.of(), List.of(), Map.of(), Set.of());
    }

    public Optional<SinkRule> match(String typeFqn, String method) {
        if (typeFqn == null) {
            return Optional.empty();
        }
        return sinkRules.stream().filter(r -> r.matches(typeFqn, method)).findFirst();
    }
}
