package com.sherlockphones.codegraph;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * 줄 단위 위험 지점 규칙. 파서 없이 정규식으로 찾으므로 후보일 뿐이고, 판단은 코드를 읽고 한다.
 *
 * @param extensions 이 규칙을 적용할 파일 확장자 (예: kt, java)
 * @param secret     찾은 값이 비밀값이면 true. snippet 에서 가린다
 */
public record LineRule(String category, String cwe, String api, Pattern pattern, Set<String> extensions, boolean secret) {

    public static LineRule of(String category, String cwe, String api, String regex, Set<String> extensions) {
        return new LineRule(category, cwe, api, Pattern.compile(regex), extensions, false);
    }

    public static LineRule secret(String what, String regex, Set<String> extensions) {
        return new LineRule("HARDCODED_SECRET", "CWE-798", "하드코딩된 비밀값: " + what, Pattern.compile(regex), extensions, true);
    }

    public boolean appliesTo(String extension) {
        return extensions.contains(extension);
    }
}
