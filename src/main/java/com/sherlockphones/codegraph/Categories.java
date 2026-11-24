package com.sherlockphones.codegraph;

import java.util.List;

/**
 * 위험 지점 분류와 조사 우선순위. 기기 안의 다른 앱·링크로 코드 실행이나 데이터 유출까지 바로 이어지는 분류가 앞이고,
 * 쓰임새를 봐야 하는 약한 암호화·난수가 뒤다.
 */
public final class Categories {

    public static final List<String> ORDER = List.of(
            "COMMAND", "CODE_LOADING", "SQL", "DESERIALIZATION", "WEBVIEW", "TLS", "INTENT", "EXPORTED", "PATH", "XXE",
            "CLEARTEXT", "HARDCODED_SECRET", "STORAGE", "LOGGING", "DEBUGGABLE", "BACKUP", "WEAK_CRYPTO", "WEAK_RANDOM");

    private Categories() {
    }

    /** 분류의 조사 우선순위 (작을수록 먼저). 모르는 분류는 맨 뒤 */
    public static int priority(String category) {
        int i = ORDER.indexOf(category);
        return i < 0 ? ORDER.size() : i;
    }
}
