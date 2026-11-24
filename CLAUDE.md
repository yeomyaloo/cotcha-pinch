# Sherlock Phones

Android(다음 단계 iOS) 앱 소스코드의 보안 취약점을 찾는 Claude Code 플러그인 + stdio MCP 서버. Claude가 판단하고, 서버는 앱 불러오기·설정 검사·코드 그래프·파일 읽기·발견 기록·보고서를 맡는다. Java 파싱·구조·호출 연결은 공용 엔진 core-code-agent(`../core-code-agent`, `com.codeagent:core-code-agent`)의 `JavaGraphSupport` 를 쓴다. GitHub 저장소 이름은 `sherlock-phones`(로컬 폴더 이름은 phonetective).

## 명령

```bash
./gradlew test                              # 테스트 (네트워크·API 키 불필요)
python -m unittest discover -s benchmark    # 벤치마크 채점 스크립트 테스트
./gradlew pluginServer                      # 플러그인용 server/lib (커밋 대상)
claude plugin validate .                    # 플러그인 구조 검사 (CLAUDE.md 경고 하나는 정상)
```

- Windows PowerShell에서는 `.\gradlew.bat`.
- core 는 GitHub Packages 에서 받는다(토큰 필요). 토큰이 없거나 core 를 같이 고칠 때는 `-PcoreCodeAgentDir=../core-code-agent`(PowerShell 에서는 따옴표로 감싼다). core 를 바꾸면 거기서 버전을 올리고 `v{version}` 태그로 배포한 뒤 `build.gradle` 의존 버전을 올린다.
- 빌드는 JDK 21 toolchain, 바이트코드는 `release 17`. Java 21 전용 API(`getFirst` 등)를 쓰지 않는다.

## 구조

- `codegraph/`: 플랫폼 공통. core 위의 앱 그래프(`CodeGraphBuilder`: 컴포넌트·JS 브리지 진입점, 아무 인증서나 믿는 TLS, 줄·설정 위험 지점), 메모리 색인(`CodeGraph`), 줄 단위 스캐너(`LineScanner`, `LineRule`), 플랫폼이 넘기는 재료(`AppScan`: `Component`, `StaticSink`, Java 규칙, 알려진 반환 타입, 브리지 애너테이션), 분류 우선순위(`Categories`).
- `android/`: `AndroidManifests`(모듈의 src/main 매니페스트, namespace), `XmlTree`(DOCTYPE·외부 엔티티를 막은 SAX, 줄 번호), `AndroidConfigChecks`(매니페스트·네트워크 보안 설정 → detector=config), `AndroidRules`(Java 규칙, 줄 규칙, 입구 메서드), `AndroidScanner`.
- iOS 는 `ios/` 에 같은 모양(설정 검사 + 줄 규칙 → `AppScan`)으로 더한다.
- 위험 지점 props `detector`: code(Java 호출), line(줄 규칙), config(설정). 새 분류는 `Categories.ORDER` 에도 넣는다. CWE 를 새로 쓰면 `findings/MobileMapping` 에 OWASP Mobile·MASVS 를 넣는다.
- 새 도구는 `SherlockTools` 에 `ToolDef` 를 추가하고 `all()` 에 넣는다. 입력 오류는 `ToolException`.

## 규칙

- **분석 대상 앱은 읽기만 한다.** 빌드, 설치, 실행하지 않는다.
- **표준 출력은 MCP 메시지 전용이다.** 로그는 표준 오류로만.
- 파일 접근은 반드시 `RepoFiles.resolve()` 로 앱 폴더 안인지 검사한다.
- 앱의 XML 은 `XmlTree` 로만 읽는다 (XXE 방지).
- 코드에서 찾은 비밀값은 도구 결과·발견·보고서에서 가린다.
- 외부로는 OSV 에 라이브러리 이름·버전만 보낸다. 테스트는 실제 OSV 에 요청하지 않는다(로컬 HttpServer 로 흉내, 프로토콜 테스트는 `SHERLOCK_PHONES_OSV=off`).
- 발견은 위협 모델의 네 공격자(other_app, link, network, device) 중 하나를 단다.
- 벤치마크(`benchmark/bank-app`)의 정답 파일은 앱 폴더 밖에 두고, 앱에 힌트 주석을 달지 않는다. 규칙을 바꾸면 `BenchmarkTest` 가 정답의 위험 지점 목록과 정확히 같은지 본다. 앱을 고치면 정답 파일의 줄 번호도 고친다.
- 서버 코드를 바꾸면 `./gradlew pluginServer` 로 `server/lib` 를 다시 만들어 커밋하고 `plugin.json` 의 `version` 을 올린다.
- 주석, 도구 설명, 결과 문구, 테스트 메서드 이름은 한국어.
- README는 영어 먼저, `---` 아래에 한국어. 둘 다 같이 고친다. 기능을 바꾸면 진행 상황, 검사 표, 도구 표, 구조 그림도 갱신한다.
- 작업이 끝나고 테스트가 통과하면 커밋하고 푸시해도 된다.
- 사용자에게 설명과 요약은 한국어로 한다.
