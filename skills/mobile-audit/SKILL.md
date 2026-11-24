---
name: mobile-audit
description: Audit an Android or iOS app's source code for security vulnerabilities with the cotcha-pinch MCP tools — check AndroidManifest.xml and the network security config, map the attack surface (exported activities/services/receivers/providers, deep links, WebView JavaScript bridges), follow entry point → sink paths, investigate each item by reading real code, record findings with the attacker who can exploit them (another app on the device, a crafted link, the network, a lost or rooted phone), re-verify every finding adversarially, and export a report mapped to the OWASP Mobile Top 10 and MASVS. Use when the user asks to security-review, audit, pentest-review or find vulnerabilities in an Android app (Java or Kotlin) — exported components, intent redirection, mutable PendingIntents, content provider SQL injection or path traversal, WebView JS bridges and file access, TLS validation turned off, cleartext traffic, tokens in SharedPreferences or logs, hardcoded secrets, weak crypto, debuggable or backup-enabled builds, vulnerable Gradle dependencies — given a local folder path or a public Git URL.
---

# Android and iOS app security audit (cotcha-pinch)

You lead a source-code security audit of an Android or iOS app using the `cotcha-pinch` MCP tools. The MCP server is the hands (manifest and config checks, code graph, file access, records); you are the brain (planning and judgment). Reply in the user's language.

Static analysis can be wrong. **Every judgment must come from reading the actual code and manifest with `read_file`.** Only read the app — never build, install or run it.

## Who attacks (threat model)

A finding must name the attacker who can actually exploit it (`attacker` in `record_finding`):
- `other_app` — a malicious app on the same phone. Sends Intents to exported components, queries content providers, listens to broadcasts, hijacks mutable PendingIntents.
- `link` — a crafted deep link or web content in a WebView. Deep-link parameters (BROWSABLE intent filters) and `@JavascriptInterface` bridges are its way in.
- `network` — someone on public Wi-Fi or a proxy (MITM). Cleartext HTTP, user-installed CAs, trust-all TrustManagers, hostname checks off, `SslErrorHandler.proceed()`.
- `device` — a lost or rooted phone, or anyone who downloads the APK. Plaintext tokens in SharedPreferences, logs, backups (`allowBackup`), `debuggable`, hardcoded secrets and keys.

## 1. Load and plan

1. `load_app` with `path` (absolute app folder, the Gradle root) or `git_url` (public https repo). Note the app id. If it reports earlier findings and the user wants a fresh audit, call `clear_findings`.
2. Map the attack surface:
   - `check_config` — manifest flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`), components exported without a permission, network security config (cleartext domains, user CAs). `debug-overrides` and `src/debug` manifests are not shipped and are ignored.
   - `list_components` — every way in: exported components with their permission, intent actions, deep links, provider authorities and the handler methods that receive input (`onCreate`, `onNewIntent`, `onReceive`, `query`, `openFile`, …), plus `JS_BRIDGE` methods, in Java or Kotlin. If a component says the class is not in the app source, it comes from a library or the Kotlin parser could not load: read it directly.
   - `list_sink_paths` — entry point → dangerous call paths through Java and Kotlin code, riskiest categories first.
   - `list_sinks` with `detector=line` — pattern candidates (WebView settings, hostname-verifier lambdas, storage, logging, secrets); trace their inputs by reading the file.
   - `check_dependencies` — Gradle (and React Native npm) libraries with known vulnerabilities from OSV. Only coordinates and versions are sent.
3. Build a short plan (aim for 6–12 items, highest risk first): COMMAND / CODE_LOADING / SQL / DESERIALIZATION / WEBVIEW / TLS / INTENT paths, then EXPORTED / PATH / CLEARTEXT / HARDCODED_SECRET / STORAGE / LOGGING, then DEBUGGABLE / BACKUP / WEAK_CRYPTO / WEAK_RANDOM. Group items in the same component or file. Also think about what patterns cannot show: exported components that act on extras without checking the caller, deep links that start sensitive flows (payments, account changes) without confirmation, and login/session handling.
4. **Get the user's approval before investigating.** Show the plan as a numbered list (for each item: the component or file, category/CWE, the attacker, one line on what you will check), then stop and ask. They may drop items, add items, or reject the plan. Do not call `read_file` or start investigating until they answer. Skip the wait only if the user already said to go ahead without confirmation, or you are running unattended. If investigation turns up follow-up work outside the plan, list it and ask again.

## iOS notes

- `load_app` reports iOS when it finds `Info.plist` or `*.entitlements`. `check_config` covers App Transport Security (arbitrary loads, exception domains with insecure HTTP or old TLS), `UIFileSharingEnabled` and `get-task-allow`.
- `list_components` shows `URL_SCHEME` (any app or web page can open `scheme://…`; the opener is not verified) and `UNIVERSAL_LINK` entries, with the file:line of the handler (`application(_:open:options:)`, `scene(_:openURLContexts:)`, `onOpenURL`, `continue userActivity`). Start there: query items and paths are attacker input (`link`, or `other_app` for URL schemes).
- Swift and Objective-C have no call graph yet: every iOS code sink is a line-rule candidate. Read the file and trace the value back yourself with `grep_code`.
- Defenses to look for: Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` instead of `UserDefaults`, `SecTrustEvaluateWithError` plus pinning before `.useCredential`, host allow-lists before loading a URL in `WKWebView`, bound SQLite parameters (`?` + `sqlite3_bind_*`), `CryptoKit` (`SHA256`, `AES.GCM`) instead of `Insecure` / CommonCrypto ECB.

## 2. Investigate (worker role)

For each item:
- Start at the entry point and read the handler. Follow attacker-controlled values — `getIntent()` extras and `getData()` URIs, provider `selection`/`uri`, deep-link query parameters, arguments of bridge methods — to the sink.
- Look for defenses with `grep_code` and the manifest: `exported="false"`, permissions with `protectionLevel="signature"`, `checkCallingPermission` / `getCallingPackage` / `Binder.getCallingUid`, `selectionArgs` binding (`?`), `getCanonicalPath` + base-dir checks, URL/host allow-lists before `loadUrl`, explicit target components and `FLAG_IMMUTABLE`, `EncryptedSharedPreferences` / Android Keystore, settings that only apply to debug `buildTypes`.
- Category notes:
  - **WEBVIEW**: what URL does it load and who controls it? Is JavaScript on? What do `@JavascriptInterface` methods return or do? `allowUniversalAccessFromFileURLs` / `allowFileAccessFromFileURLs` let a `file://` page read other origins.
  - **INTENT**: an Intent taken from extras and passed to `startActivity` lets another app open non-exported components (intent redirection, CWE-940). `PendingIntent` with an implicit base Intent and `FLAG_MUTABLE` can be hijacked (CWE-927).
  - **TLS**: a TrustManager whose `checkServerTrusted` does nothing, a HostnameVerifier that returns `true`, or `SslErrorHandler.proceed()` disables certificate checks.
  - **STORAGE / LOGGING**: only a problem for real secrets (tokens, passwords, PINs, keys), not for constant messages or encrypted storage.
  - **WEAK_CRYPTO / WEAK_RANDOM**: only when protecting secrets or generating tokens/OTPs; SHA-256 for pinning and `Random` for UI shuffling are fine.
  - **Config**: confirm the value reaches the release build (manifest merger, `buildTypes`, `manifestPlaceholders`).
- Call `record_finding` **only** when you confirmed the attacker reaches the sink unblocked. Include `attacker`, file:line evidence and a concrete attack (an `adb shell am start` / `content query` command, a malicious app snippet, or a deep link URL). Never write secret values in full — mask them.

If you can spawn subagents (Claude Code `Agent` tool), give each plan item to its own subagent in parallel with the app id, the item and these rules.

## 3. Verify (verifier role)

Switch sides. For each finding (`list_findings` with `detail=true`), assume the report may be wrong and re-read the code and manifest:
- **Entry** — is the component really exported in the shipped manifest, and without a permission the attacker can hold?
- **Input** — can that attacker really control the value?
- **Defenses** — does any control above stop it?
- **Impact** — what does the attacker gain (another app's data, tokens, code execution, a hijacked UI)? Is the severity inflated?

Then `submit_verdict`: `confirmed`, `rejected` (blocked, not reachable, debug-only), or `uncertain` (only when the deciding code is not in the app source). Use a different subagent from the investigator if you can.

## 4. Report

`export_report` (`format=markdown`; add `format=sarif` for GitHub code scanning). Each finding carries CWE, OWASP Mobile Top 10 and MASVS. Summarize for the user:
- Confirmed vulnerabilities by severity, each with location (file:line), the attacker and attack, and how to fix it.
- One line per rejected finding explaining why it was a false positive.
- The saved report path.

Do not publish vulnerability details of someone else's live, unpatched app; keep the report with the user.
