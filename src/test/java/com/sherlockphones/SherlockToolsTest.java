package com.sherlockphones;

import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.tools.Args;
import com.sherlockphones.tools.SherlockTools;
import com.sherlockphones.tools.ToolDef;
import com.sherlockphones.tools.ToolException;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.Workspace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SherlockToolsTest {

    @TempDir
    Path home;

    private SherlockTools tools;

    @BeforeEach
    void setUp() {
        Workspace workspace = new Workspace(home, List.of("github.com"), 50L * 1024 * 1024, 30);
        tools = new SherlockTools(workspace, new AppRegistry(workspace), new FindingStore(workspace.findings()));
    }

    @Test
    void 앱을_불러오면_플랫폼과_위험_지점_수를_알려준다() {
        String result = call("load_app", Map.of("path", BenchmarkTest.APP.toString()));

        assertThat(result).contains("앱 id: bank-app", "플랫폼: Android", "com.example.bank",
                "진입점(외부에 열린 컴포넌트·JS 브리지) 9", "위험 지점 34 (코드 그래프 19 · 줄 단위 규칙 8 · 설정 검사 7)",
                "입구 → 위험 지점 경로(쌍) 11개");
    }

    @Test
    void 외부에_열린_입구와_딥링크_권한_JS_브리지를_보여준다() {
        call("load_app", Map.of("path", BenchmarkTest.APP.toString()));
        String components = call("list_components", Map.of("app", "bank-app"));

        assertThat(components)
                .contains("ACTIVITY com.example.bank.MainActivity [런처]")
                .contains("ACTIVITY com.example.bank.web.WebActivity · 권한 없음 · 딥링크 bank://web")
                .contains("SERVICE com.example.bank.sync.SyncService · 권한 com.example.bank.permission.SYNC")
                .contains("PROVIDER com.example.bank.data.StatementProvider · 권한 없음 · authorities com.example.bank.statements")
                .contains("입력을 받는 메서드: StatementProvider#query(Uri,String[],String,String[],String)")
                .contains("JS_BRIDGE com.example.bank.web.BankBridge#getSessionToken()")
                .contains("ACTIVITY com.example.bank.search.PayeeSearchActivity", "Java 소스 없음")
                .doesNotContain("HelpActivity", "TransferActivity", "AvatarProvider");
    }

    @Test
    void 설정_검사는_배포_설정만_보고_비밀값은_가린다() {
        call("load_app", Map.of("path", BenchmarkTest.APP.toString()));

        String config = call("check_config", Map.of("app", "bank-app"));
        assertThat(config).contains("android:debuggable = true", "android:allowBackup = true", "설정 문제 7개",
                "평문 HTTP 허용 (*.rates.bank.example.com)", "사용자가 설치한 인증서도 신뢰 (pay.bank.example.com)",
                "M8 / MASVS-PLATFORM");
        // debug-overrides 의 사용자 인증서는 문제로 보지 않는다
        assertThat(config).doesNotContain("network_security_config.xml:23");

        String secrets = call("list_sinks", Map.of("app", "bank-app", "category", "hardcoded_secret"));
        assertThat(secrets).contains("[줄 규칙]", "CLIE****(가림)").doesNotContain("9fQ2LxT7");
        assertThat(call("list_sinks", Map.of("app", "bank-app", "detector", "config"))).contains("[설정]").doesNotContain("[줄 규칙]");
    }

    @Test
    void 발견은_공격자와_OWASP_Mobile_분류를_달아_보고한다() throws Exception {
        call("load_app", Map.of("path", BenchmarkTest.APP.toString()));
        String recorded = call("record_finding", Map.of(
                "app", "bank-app", "title", "명세서 Provider 의 SQL 인젝션", "cwe", "cwe-89", "severity", "high",
                "confidence", "high", "attacker", "other_app", "description", "selection 을 이어 붙인다",
                "evidence", List.of(Map.of("file", "app/src/main/java/com/example/bank/data/StatementProvider.java", "line", 27, "note", "rawQuery")),
                "entry_point", "PROVIDER com.example.bank.data.StatementProvider"));
        assertThat(recorded).contains("F1", "M4 / MASVS-CODE");

        assertThat(call("submit_verdict", Map.of("app", "bank-app", "finding_id", "F1", "verdict", "confirmed",
                "reasoning", "exported=true 이고 권한이 없다"))).contains("확정");

        String markdown = call("export_report", Map.of("app", "bank-app"));
        assertThat(markdown).contains("모바일 앱 보안 분석 보고서", "| F1 | 확정 | high | CWE-89 | M4 / MASVS-CODE |",
                "OWASP Mobile Top 10: M4 · Insufficient Input/Output Validation", "공격자: 기기의 다른 앱");

        String sarif = call("export_report", Map.of("app", "bank-app", "format", "sarif"));
        Path file = Path.of(sarif.substring(sarif.indexOf(':') + 1).strip());
        assertThat(Files.readString(file)).contains("\"owasp-mobile/M4\"", "\"masvs/MASVS-CODE\"", "\"attacker\" : \"other_app\"",
                "sherlock-phones");
    }

    @Test
    void 공격자가_없거나_앱_밖의_파일이면_거절한다() {
        call("load_app", Map.of("path", BenchmarkTest.APP.toString()));

        assertThatThrownBy(() -> call("read_file", Map.of("app", "bank-app", "path", "../../build.gradle")))
                .isInstanceOf(ToolException.class).hasMessageContaining("밖");
        assertThatThrownBy(() -> call("record_finding", Map.of(
                "app", "bank-app", "title", "t", "cwe", "CWE-89", "severity", "high", "confidence", "high",
                "attacker", "hacker", "description", "d",
                "evidence", List.of(Map.of("file", "app/build.gradle", "line", 1, "note", "n")))))
                .isInstanceOf(ToolException.class);
        assertThat(call("grep_code", Map.of("app", "bank-app", "pattern", "rawQuery")))
                .contains("PayeeSearchActivity.kt:22", "StatementProvider.java:27");
    }

    private String call(String name, Map<String, Object> args) {
        ToolDef tool = tools.all().stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
        return tool.handler().apply(new Args(args));
    }
}
