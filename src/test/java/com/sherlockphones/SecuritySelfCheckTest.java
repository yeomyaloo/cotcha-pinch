package com.sherlockphones;

import com.codeagent.core.model.CodeNodeKind;
import com.sherlockphones.android.AndroidScanner;
import com.sherlockphones.android.AndroidScanner.AndroidApp;
import com.sherlockphones.codegraph.CodeGraph;
import com.sherlockphones.codegraph.StaticSink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 도구 자체의 보안: 분석 대상 저장소는 믿을 수 없는 입력이다.
 */
class SecuritySelfCheckTest {

    @TempDir
    Path workspace;

    @Test
    void 매니페스트가_가리키는_네트워크_보안_설정은_앱_폴더_밖을_읽지_않는다() throws IOException {
        Path app = workspace.resolve("app-under-audit");
        // 앱 폴더 밖에 있는 (다른 프로젝트의) XML
        write(workspace.resolve("outside/res/xml/leak.xml"), """
                <network-security-config>
                    <base-config cleartextTrafficPermitted="true" />
                </network-security-config>
                """);
        write(app.resolve("src/main/AndroidManifest.xml"), """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil">
                    <application android:networkSecurityConfig="@xml/../../../../outside/res/xml/leak" />
                </manifest>
                """);

        AndroidApp android = AndroidScanner.scan(app);

        assertThat(android.scan().staticSinks()).extracting(StaticSink::filePath).noneMatch(f -> f.contains("leak"));
        assertThat(android.scan().staticSinks()).isEmpty();
    }

    @Test
    void 코드_조각에_섞인_비밀값은_가린다() throws IOException {
        write(workspace.resolve("src/main/java/com/example/Keys.java"), """
                package com.example;

                import javax.crypto.spec.SecretKeySpec;

                public class Keys {
                    public SecretKeySpec key() {
                        return new SecretKeySpec("hunter2-super-secret".getBytes(), "AES");
                    }
                }
                """);
        write(workspace.resolve("src/main/java/com/example/Crypto.kt"), """
                package com.example

                import javax.crypto.spec.SecretKeySpec

                fun spec() = SecretKeySpec("kotlin-secret-value-1".toByteArray(), "AES")
                """);

        AndroidApp android = AndroidScanner.scan(workspace);
        CodeGraph graph = CodeGraph.build(workspace, android.scan());

        assertThat(graph.nodes(CodeNodeKind.SINK)).extracting(n -> n.prop("snippet"))
                .anyMatch(s -> s.contains("\"hunt****(가림)\""))
                .anyMatch(s -> s.contains("\"kotl****(가림)\""))
                .noneMatch(s -> s.contains("super-secret") || s.contains("secret-value"));
    }

    private static void write(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
