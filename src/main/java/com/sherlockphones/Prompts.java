package com.sherlockphones;

/**
 * MCP 프롬프트와 서버 안내문. 채팅의 Claude 가 계획·조사(Worker)·검증(Verifier) 역할을 차례로 맡도록 이끈다.
 * 판단 기준은 위협 모델의 네 공격자다: 기기의 다른 앱, 조작된 링크·웹 콘텐츠, 같은 네트워크, 잃어버리거나 루팅된 폰.
 */
final class Prompts {

    private Prompts() {
    }

    static final String INSTRUCTIONS = """
            안드로이드 앱 소스코드의 보안 취약점을 찾는 도구 모음입니다 (cotcha-pinch). 판단은 Claude 가 하고, 이 서버는 매니페스트·설정 검사, 코드 그래프, 파일 읽기, 기록을 맡습니다.
            순서: load_app → check_config · list_components · list_sink_paths · list_sinks · check_dependencies → 조사할 계획을 사용자에게 보여주고 승인받기
            → 항목마다 read_file·grep_code·get_callers 로 조사 → 공격자가 실제로 닿는 것만 record_finding(공격자 표시)
            → 발견마다 반대 입장에서 다시 확인하고 submit_verdict → export_report.
            판단은 반드시 실제 코드와 매니페스트를 읽고 내립니다. 분석 대상 앱은 읽기만 하고, 빌드·설치·실행하지 않습니다.
            """;

    static String mobileAudit(String target, String maxItems) {
        String load = target.startsWith("https://")
                ? "load_app 을 git_url=\"" + target + "\" 로 호출하세요."
                : "load_app 을 path=\"" + target + "\" 로 호출하세요.";
        return """
                %s 의 모바일 앱 보안 취약점을 분석해 주세요. 아래 순서를 따르고, 모든 설명은 한국어로 씁니다.

                ## 공격자 (위협 모델)
                발견은 반드시 아래 넷 중 하나가 실제로 해낼 수 있어야 합니다.
                - other_app: 같은 폰에 깔린 악성 앱. 외부에 열린(exported) 컴포넌트에 Intent 를 보내고, Provider 를 조회하고, 브로드캐스트를 엿듣습니다.
                - link: 조작된 딥링크나 WebView 에 띄운 웹 콘텐츠. BROWSABLE 딥링크 파라미터, JS 브리지(@JavascriptInterface)로 들어옵니다.
                - network: 공용 와이파이·프록시의 누군가(MITM). 평문 HTTP, 인증서·호스트 검증을 끈 코드를 노립니다.
                - device: 잃어버리거나 루팅된 폰, 또는 APK 를 받은 누구나. 저장소·로그·백업, 하드코딩된 비밀값, debuggable 을 봅니다.

                ## 1. 준비
                %s
                이어서 check_config(매니페스트·네트워크 보안 설정), list_components(외부에 열린 입구), list_sink_paths(입구 → 위험 지점 경로),
                list_sinks(detector=line: 설정 대입·저장·로그·비밀값 같은 줄 단위 후보), check_dependencies(알려진 CVE)를 봅니다.
                위험한 것부터 최대 %s개 항목을 고릅니다: COMMAND·CODE_LOADING·SQL·DESERIALIZATION·WEBVIEW·TLS·INTENT 경로가 먼저,
                그다음 EXPORTED·PATH·CLEARTEXT·HARDCODED_SECRET·STORAGE·LOGGING, 마지막으로 DEBUGGABLE·BACKUP·WEAK_CRYPTO·WEAK_RANDOM.
                같은 컴포넌트·파일의 것은 한 항목으로 묶습니다.
                고른 항목을 번호를 붙여 보여주고(항목마다 입구 또는 파일, 분류·CWE, 공격자, 무엇을 확인할지 한 줄), 사용자에게 승인을 받습니다.
                사용자가 빼거나 더할 항목을 말하면 반영하고, 승인한 항목만 조사합니다. 거절하면 아무것도 기록하지 않고 멈춥니다.
                사용자가 답하기 전에는 read_file 로 조사를 시작하지 않습니다. 사용자가 이미 "확인 없이 바로 진행"을 원한다고 했을 때만 기다리지 않습니다.

                ## 2. 조사 (Worker 역할)
                항목마다:
                - 입구(onCreate, onNewIntent, onReceive, Provider 의 query·openFile, JS 브리지 메서드)부터 read_file 로 읽고,
                  공격자가 넣은 값(Intent extra, getData() 의 URI, selection, 딥링크 파라미터, 웹 페이지의 인자)이 위험 지점까지 어떻게 가는지 따라갑니다.
                - 막는 장치를 반드시 찾습니다: exported=false, signature 수준 권한(protectionLevel), checkCallingPermission·getCallingPackage,
                  selectionArgs(?) 바인딩, 경로 정규화(getCanonicalPath)와 기준 폴더 확인, URL·호스트 허용 목록, Intent 의 대상 컴포넌트 확인,
                  FLAG_IMMUTABLE, EncryptedSharedPreferences·Keystore, 릴리스 빌드에서만 쓰는 설정(buildTypes).
                - 줄 규칙 후보는 경로가 없을 수 있으니 파일을 직접 읽고 입력 출처를 확인합니다.
                - iOS 는 URL_SCHEME·UNIVERSAL_LINK 입구의 처리 함수(list_components 가 위치를 알려줌)에서 시작합니다. Swift·Objective-C 는 아직 호출 경로가 없으니
                  grep_code 로 값을 직접 따라갑니다. Keychain 접근성, SecTrustEvaluateWithError·인증서 고정, WKWebView URL 허용 목록, sqlite3_bind 를 막는 장치로 봅니다.
                - WebView 는 setJavaScriptEnabled, addJavascriptInterface 로 노출한 메서드, 띄우는 URL 의 출처를 함께 봅니다.
                - 약한 암호화·난수는 토큰·비밀번호·암호화 키처럼 보안에 쓰일 때만, 로그·저장은 실제로 민감한 값일 때만 취약합니다.
                - 설정 문제(debuggable, allowBackup, 평문 HTTP, 사용자 인증서 신뢰)는 배포 빌드에 들어가는지(src/main, buildTypes)와 영향을 확인합니다.
                - 라이브러리 취약점은 취약한 기능을 앱이 실제로 쓸 때만 발견으로 기록하고, 아니면 고친 버전으로 올리라는 권고로만 남깁니다.
                - 공격자가 막힘 없이 닿는다는 것을 확인했을 때만 record_finding 으로 기록합니다. attacker 를 반드시 넣고,
                  근거 위치(파일:줄)와 구체적인 공격 예시(adb shell am start / content query / 악성 앱 코드 / 딥링크 URL)를 씁니다. 비밀값은 가립니다.
                Claude Code 처럼 서브에이전트를 쓸 수 있는 환경이면, 항목마다 서브에이전트에게 맡겨 나란히 조사해도 됩니다.

                ## 3. 검증 (Verifier 역할)
                조사가 끝나면 입장을 바꿔, 기록한 발견마다 "이 보고서는 틀렸을 수 있다"고 보고 독립적으로 다시 확인합니다.
                - 입구: 그 컴포넌트가 정말 외부에 열려 있는가(매니페스트, 권한, 배포 빌드의 매니페스트)?
                - 입력: 정말 그 공격자가 조절할 수 있는 값인가?
                - 막는 장치: 위의 장치 중 하나라도 공격을 막는가?
                - 영향: 성공하면 무엇을 얻는가(다른 앱의 데이터, 토큰, 코드 실행)? 심각도가 과장되지 않았는가?
                판단이 서면 submit_verdict 로 confirmed / rejected / uncertain 을 기록합니다. uncertain 은 근거 코드가 앱 소스에 없을 때만 씁니다.
                서브에이전트를 쓸 수 있으면 조사와 다른 서브에이전트에게 검증을 맡깁니다.

                ## 4. 보고
                export_report(format=markdown) 로 보고서를 저장하고, 확정된 취약점을 심각도 순으로 요약해 주세요.
                각 항목에 위치(파일:줄), 공격자와 공격 예시, OWASP Mobile Top 10·MASVS, 고치는 방법을 짧게 붙입니다.
                기각한 발견은 왜 오탐인지 한 줄씩 덧붙입니다.
                """.formatted(target, load, maxItems);
    }

    static String verifyFindings(String app) {
        return """
                앱 %s 의 검증 대기 발견을 다시 검증해 주세요. 모든 설명은 한국어로 씁니다.
                list_findings(app="%s", status="OPEN", detail=true) 로 목록을 보고, 발견마다 보고서를 그대로 믿지 말고
                read_file·grep_code·get_callers 로 코드와 매니페스트를 직접 다시 읽어 입구가 열려 있는지, 입력이 그 공격자에게서 오는지,
                막는 장치, 영향을 확인합니다. 판단이 서면 submit_verdict 로 confirmed / rejected / uncertain 을 기록하고,
                끝나면 판정 결과를 표로 요약해 주세요.
                """.formatted(app, app);
    }
}
