package com.sherlockphones;

import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.ios.IosScanner;
import com.sherlockphones.tools.Args;
import com.sherlockphones.tools.SherlockTools;
import com.sherlockphones.tools.ToolDef;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.Workspace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IosTest {

    private static final Path APP = Path.of("benchmark/bank-ios").toAbsolutePath();

    @TempDir
    Path home;

    @Test
    void iOS_설정과_입구를_보여주고_테스트_번들은_건너뛴다() {
        SherlockTools tools = tools();
        assertThat(call(tools, "load_app", Map.of("path", APP.toString())))
                .contains("플랫폼: iOS · Info.plist 1개, entitlements 1개", "위험 지점 21 (코드 그래프 0 · 줄 단위 규칙 17 · 설정 검사 4)");

        assertThat(call(tools, "check_config", Map.of("app", "bank-ios")))
                .contains("NSAppTransportSecurity = 있음", "get-task-allow = true", "rates.bank.example.com 에 평문 HTTP 허용",
                        "legacy.bank.example.com 에 TLSv1.0 허용", "M5 / MASVS-NETWORK")
                .doesNotContain("pay.bank.example.com 에 TLSv1.2");

        assertThat(call(tools, "list_components", Map.of("app", "bank-ios")))
                .contains("URL_SCHEME bankapp://", "UNIVERSAL_LINK applinks:bank.example.com", "딥링크 https://bank.example.com/",
                        "URL 을 받는 곳: BankiOS/AppDelegate.swift:8");

        assertThat(call(tools, "list_sinks", Map.of("app", "bank-ios", "category", "hardcoded_secret")))
                .contains("clie****(가림)").doesNotContain("9fQ2LxT7").doesNotContain("BankiOSTests");
    }

    @Test
    void 내부_선언이_있는_plist_는_읽지_않는다() throws IOException {
        Path root = home.resolve("evil");
        Files.createDirectories(root.resolve("App"));
        Files.writeString(root.resolve("App/Info.plist"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
                <plist version="1.0"><dict><key>CFBundleName</key><string>&xxe;</string></dict></plist>
                """);

        var ios = IosScanner.scan(root);

        assertThat(ios.infoPlists()).isEmpty();
        assertThat(ios.errors()).singleElement().asString().contains("XML 을 읽지 못함");
    }

    private SherlockTools tools() {
        Workspace workspace = new Workspace(home, List.of("github.com"), 50L * 1024 * 1024, 30);
        return new SherlockTools(workspace, new AppRegistry(workspace), new FindingStore(workspace.findings()));
    }

    private static String call(SherlockTools tools, String name, Map<String, Object> args) {
        ToolDef tool = tools.all().stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
        return tool.handler().apply(new Args(args));
    }
}
