package com.sherlockphones.codegraph;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 도구 출력·보고서에 비밀값이 그대로 나가지 않게 가린다. 찾은 값의 앞 4글자만 남긴다.
 * 줄 단위 규칙(비밀값 규칙)과 코드 그래프 위험 지점의 snippet 이 같은 패턴을 쓴다.
 */
public final class SecretMasker {

    /** 이름과 패턴. 줄 단위 HARDCODED_SECRET 규칙도 이 목록으로 만든다 */
    public record SecretPattern(String what, Pattern pattern) {
    }

    public static final List<SecretPattern> PATTERNS = List.of(
            secret("AWS 액세스 키", "\\bAKIA[0-9A-Z]{16}\\b"),
            secret("Google API 키", "\\bAIza[0-9A-Za-z_\\-]{35}\\b"),
            secret("Stripe 비밀 키", "\\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\\b"),
            secret("GitHub 토큰", "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"),
            secret("Slack 토큰", "\\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            secret("LLM API 키", "\\bsk-(?:ant-|proj-)?[A-Za-z0-9_\\-]{20,}"),
            secret("개인 키", "-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"));

    /** 8글자 이상 문자열 상수 */
    private static final Pattern LONG_LITERAL = Pattern.compile("\"([^\"\\\\]{8,})\"");

    private SecretMasker() {
    }

    /** 문자열 상수 자체가 비밀일 수 있는 분류 (하드코딩된 키·비밀값) */
    public static boolean mayHoldSecretLiteral(String cwe) {
        return "CWE-321".equals(cwe) || "CWE-798".equals(cwe);
    }

    /** 알려진 비밀값 패턴을 가린다 */
    public static String mask(String text) {
        if (text == null) {
            return null;
        }
        String result = text;
        for (SecretPattern p : PATTERNS) {
            result = maskAll(result, p.pattern());
        }
        return result;
    }

    /** 하드코딩된 키처럼 문자열 상수 자체가 비밀일 수 있는 곳: 8글자 이상 문자열 상수도 가린다 */
    public static String maskLiterals(String text) {
        if (text == null) {
            return null;
        }
        Matcher m = LONG_LITERAL.matcher(mask(text));
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement("\"" + hide(m.group(1)) + "\""));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    static String hide(String value) {
        return value.length() <= 4 ? "****" : value.substring(0, 4) + "****(가림)";
    }

    private static String maskAll(String text, Pattern pattern) {
        Matcher m = pattern.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(hide(m.group())));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static SecretPattern secret(String what, String regex) {
        return new SecretPattern(what, Pattern.compile(regex));
    }
}
