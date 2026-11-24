package com.sherlockphones.android;

import com.sherlockphones.codegraph.LineRule;
import com.sherlockphones.codegraph.SinkRule;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 안드로이드 위험 지점 규칙.
 * - JAVA_RULES: Java 코드의 호출을 코드 그래프로 찾는다 (진입점에서 이어지는 경로를 알 수 있다).
 * - LINE_RULES: Kotlin 은 파서가 없어서 줄 단위로 찾는다. 저장소·로그·비밀값처럼 호출 하나로 잡기 어려운 것은 Java 도 줄 단위로 본다.
 */
public final class AndroidRules {

    private static final Set<String> KT = Set.of("kt");
    private static final Set<String> CODE = Set.of("kt", "java");
    private static final Set<String> SECRET_FILES = Set.of("kt", "java", "xml", "properties", "gradle", "kts", "json");

    private static final String[] SQLITE_METHODS = {
            "rawQuery", "rawQueryWithFactory", "execSQL", "query", "queryWithFactory", "update", "delete", "compileStatement"
    };

    public static final List<SinkRule> JAVA_RULES = List.of(
            // SQL 인젝션 (ContentProvider 의 selection 을 이어 붙이는 경우가 많다)
            rule("android.database.sqlite.SQLiteDatabase", "SQL", "CWE-89", SQLITE_METHODS),
            rule("androidx.sqlite.db.SupportSQLiteDatabase", "SQL", "CWE-89", "query", "execSQL", "update", "delete", "compileStatement"),
            rule("android.database.sqlite.SQLiteQueryBuilder", "SQL", "CWE-89", "query", "appendWhere", "buildQuery"),
            // 명령 실행, 코드 동적 로딩
            rule("java.lang.Runtime", "COMMAND", "CWE-78", "exec"),
            rule("java.lang.ProcessBuilder", "COMMAND", "CWE-78", "<init>", "command"),
            rule("dalvik.system.DexClassLoader", "CODE_LOADING", "CWE-94", "<init>"),
            rule("dalvik.system.PathClassLoader", "CODE_LOADING", "CWE-94", "<init>"),
            rule("dalvik.system.InMemoryDexClassLoader", "CODE_LOADING", "CWE-94", "<init>"),
            // 역직렬화 (다른 앱이 보낸 Intent 의 Serializable)
            rule("java.io.ObjectInputStream", "DESERIALIZATION", "CWE-502", "readObject", "readUnshared"),
            rule("android.content.Intent", "DESERIALIZATION", "CWE-502", "getSerializableExtra"),
            rule("android.os.Bundle", "DESERIALIZATION", "CWE-502", "getSerializable"),
            // WebView: 신뢰할 수 없는 콘텐츠를 띄우거나, 웹 페이지가 앱 코드를 부르게 하는 곳
            rule("android.webkit.WebView", "WEBVIEW", "CWE-749", "addJavascriptInterface"),
            rule("android.webkit.WebView", "WEBVIEW", "CWE-79", "loadUrl", "loadData", "loadDataWithBaseURL", "postUrl", "evaluateJavascript"),
            rule("android.webkit.WebSettings", "WEBVIEW", "CWE-749", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"),
            // TLS 검증 끄기
            rule("android.webkit.SslErrorHandler", "TLS", "CWE-295", "proceed"),
            rule("javax.net.ssl.HttpsURLConnection", "TLS", "CWE-295", "setHostnameVerifier", "setDefaultHostnameVerifier"),
            // Intent: 다른 앱이 넣은 Intent 를 그대로 띄우기(리다이렉션), 다른 앱이 바꿀 수 있는 PendingIntent
            rule("android.content.Intent", "INTENT", "CWE-940", "getParcelableExtra"),
            rule("android.app.PendingIntent", "INTENT", "CWE-927", "getActivity", "getActivities", "getBroadcast", "getService",
                    "getForegroundService"),
            // 파일 경로
            rule("java.io.File", "PATH", "CWE-22", "<init>"),
            rule("java.io.FileInputStream", "PATH", "CWE-22", "<init>"),
            rule("java.io.FileOutputStream", "PATH", "CWE-22", "<init>"),
            rule("java.io.FileReader", "PATH", "CWE-22", "<init>"),
            rule("java.io.FileWriter", "PATH", "CWE-22", "<init>"),
            rule("java.io.RandomAccessFile", "PATH", "CWE-22", "<init>"),
            // XXE (안드로이드 기본 XmlPullParser 는 안전하지만 DOM·SAX 는 설정을 봐야 한다)
            rule("javax.xml.parsers.DocumentBuilder", "XXE", "CWE-611", "parse"),
            rule("javax.xml.parsers.SAXParser", "XXE", "CWE-611", "parse"),
            rule("org.xml.sax.XMLReader", "XXE", "CWE-611", "parse"),
            // 약한 암호화·하드코딩된 키·예측 가능한 난수
            rule("java.security.MessageDigest", "WEAK_CRYPTO", "CWE-328", "getInstance"),
            rule("javax.crypto.Cipher", "WEAK_CRYPTO", "CWE-327", "getInstance"),
            rule("javax.crypto.spec.SecretKeySpec", "WEAK_CRYPTO", "CWE-321", "<init>"),
            rule("java.util.Random", "WEAK_RANDOM", "CWE-330", "<init>"),
            rule("java.lang.Math", "WEAK_RANDOM", "CWE-330", "random"));

    private static final String SENSITIVE = "(?i:token|password|passwd|secret|session|jwt|api_?key|credential|pin_?code|otp)";

    public static final List<LineRule> LINE_RULES = List.of(
            // Kotlin: Java 규칙과 같은 것을 줄 단위로
            LineRule.of("SQL", "CWE-89", "SQLiteDatabase.rawQuery / execSQL", "\\.(?:rawQuery|rawQueryWithFactory|execSQL)\\s*\\(", KT),
            LineRule.of("COMMAND", "CWE-78", "Runtime.exec / ProcessBuilder", "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|\\bProcessBuilder\\s*\\(", KT),
            LineRule.of("CODE_LOADING", "CWE-94", "동적 코드 로딩 (DexClassLoader 등)", "\\b(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\\s*\\(", KT),
            LineRule.of("DESERIALIZATION", "CWE-502", "Serializable 역직렬화", "\\bgetSerializable(?:Extra)?\\s*[(<]|\\bObjectInputStream\\s*\\(", KT),
            LineRule.of("WEBVIEW", "CWE-749", "WebView.addJavascriptInterface", "\\.addJavascriptInterface\\s*\\(", KT),
            LineRule.of("WEBVIEW", "CWE-749", "WebView 파일 URL 접근 허용",
                    "allow(?:Universal|File)AccessFromFileURLs\\s*=\\s*true|setAllow(?:Universal|File)AccessFromFileURLs\\s*\\(\\s*true", KT),
            LineRule.of("WEBVIEW", "CWE-79", "WebView.loadUrl / loadData / evaluateJavascript",
                    "\\.(?:loadUrl|loadData|loadDataWithBaseURL|postUrl|evaluateJavascript)\\s*\\(", KT),
            LineRule.of("TLS", "CWE-295", "SslErrorHandler.proceed (인증서 오류 무시)", "\\.proceed\\s*\\(\\s*\\)", KT),
            LineRule.of("TLS", "CWE-295", "모든 호스트 이름 허용",
                    "ALLOW_ALL_HOSTNAME_VERIFIER|(?:hostnameVerifier|HostnameVerifier)\\s*\\{\\s*_\\s*,\\s*_\\s*->\\s*true", KT),
            LineRule.of("TLS", "CWE-295", "X509TrustManager.checkServerTrusted 비어 있음 (모든 인증서 허용)",
                    "fun\\s+checkServerTrusted\\s*\\([^)]*\\)\\s*(?:\\{\\s*}|=\\s*Unit|\\{\\s*$)", KT),
            LineRule.of("INTENT", "CWE-940", "Intent.getParcelableExtra (받은 Intent 를 다시 띄우면 리다이렉션)", "\\bgetParcelableExtra\\s*[(<]", KT),
            LineRule.of("INTENT", "CWE-927", "PendingIntent 생성",
                    "PendingIntent\\.get(?:Activity|Activities|Broadcast|Service|ForegroundService)\\s*\\(", KT),
            LineRule.of("PATH", "CWE-22", "File 생성", "(?<![\\w.])File\\s*\\(", KT),
            LineRule.of("WEAK_CRYPTO", "CWE-328", "약한 해시 (MD5, SHA-1)", "MessageDigest\\.getInstance\\s*\\(\\s*\"(?i:MD5|MD2|SHA-?1)\"", KT),
            LineRule.of("WEAK_CRYPTO", "CWE-327", "약한 암호 (DES, RC4, ECB)",
                    "Cipher\\.getInstance\\s*\\(\\s*\"(?i:DES|DESede|RC4|RC2|Blowfish|AES\"|AES/ECB|[^\"]*/ECB/)", KT),
            LineRule.of("WEAK_CRYPTO", "CWE-321", "하드코딩된 암호 키 (SecretKeySpec)", "\\bSecretKeySpec\\s*\\(\\s*\"", KT),
            LineRule.of("WEAK_RANDOM", "CWE-330", "java.util.Random", "\\bjava\\.util\\.Random\\s*\\(|(?<![\\w.])Random\\s*\\(", KT),
            // Kotlin·Java 모두: 호출 하나로 잡기 어려운 저장·로그 문제
            LineRule.of("STORAGE", "CWE-312", "SharedPreferences 에 민감 정보 저장",
                    "\\.put(?:String|StringSet)\\s*\\(\\s*\"[^\"]*" + SENSITIVE, CODE),
            LineRule.of("STORAGE", "CWE-732", "다른 앱이 읽고 쓸 수 있는 파일 (MODE_WORLD_*)", "\\bMODE_WORLD_(?:READABLE|WRITEABLE)\\b", CODE),
            LineRule.of("STORAGE", "CWE-922", "외부 저장소 사용", "\\bgetExternalStorage(?:Directory|PublicDirectory)\\s*\\(", CODE),
            LineRule.of("LOGGING", "CWE-532", "로그에 민감 정보", "\\bLog\\.(?:v|d|i|w|e|wtf)\\s*\\(.*" + SENSITIVE, CODE),
            // 비밀값 (APK 를 풀면 누구나 볼 수 있다)
            LineRule.secret("AWS 액세스 키", "\\bAKIA[0-9A-Z]{16}\\b", SECRET_FILES),
            LineRule.secret("Google API 키", "\\bAIza[0-9A-Za-z_\\-]{35}\\b", SECRET_FILES),
            LineRule.secret("Stripe 비밀 키", "\\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\\b", SECRET_FILES),
            LineRule.secret("GitHub 토큰", "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b", SECRET_FILES),
            LineRule.secret("Slack 토큰", "\\bxox[abprs]-[A-Za-z0-9-]{10,}", SECRET_FILES),
            LineRule.secret("LLM API 키", "\\bsk-(?:ant-|proj-)?[A-Za-z0-9_\\-]{20,}", SECRET_FILES),
            LineRule.secret("개인 키", "-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", SECRET_FILES),
            LineRule.secret("비밀값 대입",
                    "(?i)\\b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|private[_-]?key|password|passwd)\\b"
                            + "\\s*[:=]\\s*\"[^\"\\s$]{8,}\"", Set.of("kt", "java")));

    /** 라이브러리 jar 없이 반환 타입을 알 수 있는 프레임워크 메서드 (getIntent().getStringExtra(...) 같은 호출의 대상 타입) */
    public static final Map<String, String> KNOWN_RETURN_TYPES = Map.ofEntries(
            Map.entry("getIntent", "android.content.Intent"),
            Map.entry("getData", "android.net.Uri"),
            Map.entry("getExtras", "android.os.Bundle"),
            Map.entry("getSettings", "android.webkit.WebSettings"),
            Map.entry("getWritableDatabase", "android.database.sqlite.SQLiteDatabase"),
            Map.entry("getReadableDatabase", "android.database.sqlite.SQLiteDatabase"),
            Map.entry("getContext", "android.content.Context"),
            Map.entry("requireContext", "android.content.Context"),
            Map.entry("getApplicationContext", "android.content.Context"),
            Map.entry("getContentResolver", "android.content.ContentResolver"),
            Map.entry("getRuntime", "java.lang.Runtime"));

    /** 웹 페이지의 자바스크립트가 부를 수 있는 메서드 표시 */
    public static final Set<String> BRIDGE_ANNOTATIONS = Set.of("android.webkit.JavascriptInterface");

    /** 컴포넌트 종류별로 다른 앱이 보낸 입력을 받는 메서드 */
    public static final Map<String, List<String>> HANDLERS = Map.of(
            "ACTIVITY", List.of("onCreate", "onNewIntent", "onStart", "onResume", "onActivityResult"),
            "SERVICE", List.of("onStartCommand", "onBind", "onHandleIntent", "onStart", "handleMessage"),
            "RECEIVER", List.of("onReceive"),
            "PROVIDER", List.of("query", "insert", "update", "delete", "bulkInsert", "openFile", "openAssetFile",
                    "openTypedAssetFile", "call"));

    private AndroidRules() {
    }

    private static SinkRule rule(String type, String category, String cwe, String... methods) {
        return new SinkRule(type, Set.of(methods), category, cwe);
    }
}
