package com.sherlockphones.ios;

import com.sherlockphones.codegraph.LineRule;
import com.sherlockphones.codegraph.SecretMasker;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * iOS 줄 단위 규칙 (Swift, Objective-C). 아직 Swift 파서가 없어서 호출 경로 없이 후보만 찾는다.
 */
public final class IosRules {

    private static final Set<String> CODE = Set.of("swift", "m", "mm");
    /** 비밀값을 찾을 파일. json·xml 등은 안드로이드 규칙이 이미 본다 */
    private static final Set<String> SECRET_FILES = Set.of("swift", "m", "mm", "h", "plist", "xcconfig", "strings");
    private static final String SENSITIVE = "(?i:token|password|passwd|secret|session|jwt|api_?key|credential|pin_?code|otp)";

    public static final List<LineRule> LINE_RULES = lineRules();

    private IosRules() {
    }

    private static List<LineRule> lineRules() {
        List<LineRule> rules = new ArrayList<>(List.of(
                // 데이터 저장 (잃어버리거나 루팅·탈옥된 폰, 백업)
                LineRule.of("STORAGE", "CWE-312", "UserDefaults 에 민감 정보 저장",
                        "UserDefaults[^\\n]*\\.set(?:Value)?\\s*\\(.*" + SENSITIVE
                                + "|\\bsetObject:.*forKey:\\s*@\"[^\"]*" + SENSITIVE, CODE),
                LineRule.of("STORAGE", "CWE-922", "Keychain 접근성 kSecAttrAccessibleAlways (잠긴 폰에서도 읽힘)",
                        "\\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\\b", CODE),
                LineRule.of("LOGGING", "CWE-532", "로그에 민감 정보", "\\b(?:print|debugPrint|NSLog|os_log)\\s*\\(.*" + SENSITIVE, CODE),
                // 인증서 검증 끄기 (같은 네트워크의 누군가)
                LineRule.of("TLS", "CWE-295", "URLSession 인증 요청에 서버 인증서를 그대로 믿음",
                        "\\.useCredential\\s*,\\s*URLCredential\\s*\\(\\s*trust|NSURLSessionAuthChallengeUseCredential", CODE),
                LineRule.of("TLS", "CWE-295", "인증서 검증 끄기 (allowsAnyHTTPSCertificate, Alamofire DisabledTrustEvaluator)",
                        "allowsAnyHTTPSCertificate|setAllowsAnyHTTPSCertificate|DisabledTrustEvaluator|DisabledEvaluator", CODE),
                // WebView (조작된 링크·웹 콘텐츠)
                LineRule.of("WEBVIEW", "CWE-749", "WKWebView 자바스크립트 브리지 (WKScriptMessageHandler)",
                        "userContentController\\.add\\s*\\(|addScriptMessageHandler", CODE),
                LineRule.of("WEBVIEW", "CWE-749", "UIWebView (지원 중단, 보안 설정이 약함)", "\\bUIWebView\\b", CODE),
                LineRule.of("WEBVIEW", "CWE-79", "WKWebView 에 HTML·URL·스크립트 넣기",
                        "\\.loadHTMLString\\s*\\(|\\.evaluateJavaScript\\s*\\(|\\.load\\s*\\(\\s*URLRequest\\s*\\("
                                // Objective-C 메시지: [webView evaluateJavaScript:… / loadHTMLString:… / loadRequest:…]
                                + "|\\s(?:loadHTMLString|evaluateJavaScript|loadRequest):", CODE),
                // SQL
                LineRule.of("SQL", "CWE-89", "SQLite 쿼리 (sqlite3_exec / prepare, FMDB)",
                        "\\bsqlite3_(?:exec|prepare(?:_v2|_v3)?)\\s*\\(|\\.execute(?:Query|Update)\\s*\\(", CODE),
                // 암호·난수
                LineRule.of("WEAK_CRYPTO", "CWE-328", "약한 해시 (MD5, SHA-1)", "\\bCC_(?:MD5|SHA1)\\s*\\(|\\bInsecure\\.(?:MD5|SHA1)\\b", CODE),
                LineRule.of("WEAK_CRYPTO", "CWE-327", "약한 암호 (DES, RC4, ECB)",
                        "\\bkCCAlgorithm(?:DES|3DES|RC4|RC2|Blowfish)\\b|\\bkCCOptionECBMode\\b", CODE),
                LineRule.of("WEAK_RANDOM", "CWE-330", "예측 가능한 난수 (rand, random)", "(?<![\\w.])(?:rand|random|srand|srandom)\\s*\\(", CODE)));
        SecretMasker.PATTERNS.forEach(p -> rules.add(
                new LineRule("HARDCODED_SECRET", "CWE-798", "하드코딩된 비밀값: " + p.what(), p.pattern(), SECRET_FILES, true)));
        rules.add(LineRule.secret("비밀값 대입",
                "(?i)\\b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|private[_-]?key|password|passwd)\\b"
                        + "\\s*[:=]\\s*@?\"[^\"\\s$]{8,}\"", CODE));
        return List.copyOf(rules);
    }
}
