package com.sherlockphones.codegraph;

/**
 * 코드 그래프의 호출 분석 없이 찾은 위험 지점. 줄 단위 규칙(파서가 없는 Kotlin 등)이나 설정 파일 검사(매니페스트 등)에서 나온다.
 *
 * @param detector line(줄 단위 규칙) 또는 config(설정 파일 검사)
 * @param snippet  코드 한 줄. 비밀값은 가려져 있다
 */
public record StaticSink(String filePath, int line, int column, String category, String cwe, String api, String snippet,
                         String detector) {

    public static final String LINE = "line";
    public static final String CONFIG = "config";
}
