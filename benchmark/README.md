# Benchmark

An evaluation harness: does an audit find the real vulnerabilities, skip the safe look-alikes, and reach the same conclusions when repeated?

| File | What it is |
|---|---|
| `bank-app/` | A small Android banking app (Gradle layout, Java and Kotlin) with **23 real vulnerabilities** (7 config, 13 Java, 3 Kotlin) and **11 safe look-alikes**: a bound query next to a concatenated one, a non-exported provider with a canonical-path check next to an exported one without, an immutable explicit `PendingIntent` next to a mutable implicit one, encrypted next to plain `SharedPreferences`, SHA-256 pinning next to a trust-all `TrustManager`, and so on. No hint comments. |
| `bank-ios/`, `bank-ios.expected.json` | The same for iOS (Swift and Objective-C): **15 real vulnerabilities** (4 Info.plist / entitlements, 11 code) and **6 traps**: plain vs. pinned `URLSession` trust, a string-built `sqlite3_exec` vs. a bound `sqlite3_prepare_v2`, MD5 for a PIN vs. for a cache key, and so on. Swift is parsed, so two of them have call paths: the URL scheme → `sqlite3_exec`, and the `WKScriptMessageHandler` bridge → `evaluateJavaScript`. |
| `bank-app.expected.json` | The answer key: file, line range, sink line, accepted CWEs, entry point and attacker of each item. It lives **outside** `bank-app/` so the agent cannot read it while auditing. |
| `score.py` | Scores SARIF reports against the answer key: recall, precision, trap false positives, wrong CWE, duplicates, and consistency across runs. |
| `test_score.py` | Tests for the scoring rules. |

`BenchmarkTest` (part of `./gradlew test`, runs in CI) checks that every vulnerability and trap shows up in `list_sinks`, nothing else does, and each code vulnerability with an entry point shows up in `list_sink_paths`.

## Scoring an audit (manual)

1. In Claude Code, start a fresh session per run and ask: "Audit the Android app at `<absolute path>/benchmark/bank-app`" (or `bank-ios`). Approve the plan.
2. At the end, have Claude call `export_report` with `format: sarif`, and keep the file as `report-1.sarif`. Run `clear_findings` before the next run.
3. Score:

```bash
python benchmark/score.py benchmark/bank-app.expected.json report-1.sarif report-2.sarif report-3.sarif
python benchmark/score.py benchmark/bank-app.expected.json report-*.sarif --confirmed-only
```

**Results so far:** one blind run on 2026-11-25 (a fresh agent that never saw the answer key, using the plugin tools through a command-line runner; plugin 0.9.x, `bank-app` only): recall 100% (23/23), precision 100%, trap false positives 0/11. One run says nothing about consistency, and that agent also did the verification pass itself, so it was not independent.

**iOS:** one blind run on 2026-11-25 on `bank-ios` (plugin 0.9.x): recall 100% (15/15), precision 100%, trap false positives 0/6. This time a separate agent did the verification pass, given only the findings and the app path. Its caveat: several flawed pieces (APIClient, TokenStore.save, LegacyLogin) are never called inside the app, so their real impact depends on use, and `get-task-allow` matters only if it reaches a release build.

Rules: a finding points at an item when one of its locations is inside the item's file and line range. With an accepted CWE it is a hit, with another CWE a wrong category. Pointing at a trap is a trap false positive; pointing at nothing is another false positive. Rejected findings are ignored. Consistency is the share of items with the same outcome in every run, plus the mean Jaccard similarity between runs.

---

# 벤치마크

분석이 진짜 취약점을 찾는지, 비슷하지만 안전한 코드는 넘기는지, 다시 돌려도 같은 결론인지 재는 평가 하네스다.

| 파일 | 내용 |
|---|---|
| `bank-app/` | 작은 안드로이드 은행 앱(Gradle 구조, Java·Kotlin). **진짜 취약점 23개**(설정 7, Java 13, Kotlin 3)와 **안전한 함정 11개**. 바인드 변수 쿼리와 이어 붙인 쿼리, canonical 경로를 확인하는 닫힌 Provider 와 확인 없는 열린 Provider, 대상이 정해진 IMMUTABLE PendingIntent 와 대상 없는 MUTABLE PendingIntent, 암호화한 SharedPreferences 와 평문, SHA-256 인증서 고정과 모든 인증서를 믿는 TrustManager 처럼 짝을 이룬다. 힌트 주석은 없다. |
| `bank-ios/`, `bank-ios.expected.json` | iOS(Swift·Objective-C) 판. **진짜 취약점 15개**(Info.plist·entitlements 4, 코드 11)와 **함정 6개**: 그대로 믿는 `URLSession` 과 인증서 고정, 문자열을 이어 붙인 `sqlite3_exec` 와 바인드한 `sqlite3_prepare_v2`, PIN 용 MD5 와 캐시 키용 MD5 등. Swift 를 파싱하므로 그중 둘은 호출 경로가 있다: URL 스킴 → `sqlite3_exec`, `WKScriptMessageHandler` 브리지 → `evaluateJavaScript`. |
| `bank-app.expected.json` | 정답 파일. 항목마다 파일, 줄 범위, 위험 지점 줄, 인정하는 CWE, 입구, 공격자. 분석 중에 읽지 못하도록 `bank-app/` **밖**에 둔다. |
| `score.py` | SARIF 보고서를 정답과 비교해 채점한다. 재현율, 정밀도, 함정 오탐, 분류 틀림, 중복, 실행 간 일관성. |
| `test_score.py` | 채점 규칙 테스트. |

`BenchmarkTest`(`./gradlew test` 에 포함, CI 에서 돈다)는 정답의 취약점과 함정이 모두 `list_sinks` 에 나오고 그 밖의 것은 없으며, 입구가 있는 코드 취약점은 `list_sink_paths` 에도 나오는지 확인한다.

## 분석 채점하기 (수동)

1. 실행마다 Claude Code 새 세션에서 "`<절대 경로>/benchmark/bank-app` 안드로이드 앱 보안 검사해줘"라고 하고 계획을 승인한다.
2. 끝나면 `export_report` 를 `format: sarif` 로 불러 `report-1.sarif` 로 둔다. 다음 실행 전에 `clear_findings`.
3. 채점한다 (위 명령).

**지금까지 결과:** 2026-11-25 블라인드 실행 1번(정답을 본 적 없는 새 에이전트가 명령줄 실행기로 플러그인 도구를 씀, 플러그인 0.9.x, `bank-app` 만): 재현율 100%(23/23), 정밀도 100%, 함정 오탐 0/11. 한 번이라 일관성은 알 수 없고, 같은 에이전트가 검증까지 해서 독립 검증은 아니다.

**iOS:** 2026-11-25 `bank-ios` 블라인드 실행 1번(플러그인 0.9.x): 재현율 100%(15/15), 정밀도 100%, 함정 오탐 0/6. 이번에는 발견 목록과 앱 경로만 받은 별도 에이전트가 검증했다. 그 에이전트의 단서: 결함 있는 코드 일부(APIClient, TokenStore.save, LegacyLogin)는 앱 안에서 부르는 곳이 없어서 실제 영향은 쓰이는지에 달렸고, `get-task-allow` 는 배포 빌드에 들어갈 때만 문제다.

규칙: 발견의 위치 중 하나가 항목의 파일·줄 범위 안에 있으면 그 항목을 가리킨 것이다. CWE 가 인정 목록에 있으면 맞힌 것, 다르면 분류 틀림이다. 함정을 가리키면 함정 오탐, 아무것도 가리키지 않으면 기타 오탐이다. 기각된 발견은 빼고 센다. 일관성은 모든 실행에서 같은 결론이 난 항목의 비율과 실행 간 평균 자카드 유사도다.
