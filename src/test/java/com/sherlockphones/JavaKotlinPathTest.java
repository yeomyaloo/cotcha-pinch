package com.sherlockphones;

import com.sherlockphones.android.AndroidScanner;
import com.sherlockphones.codegraph.CodeGraph;
import com.sherlockphones.codegraph.CodeGraph.SinkPath;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/** 안드로이드 앱에서 Java ↔ Kotlin 을 오가는 호출도 입구 → 위험 지점 경로로 이어지는지 */
class JavaKotlinPathTest {

    @TempDir
    Path app;

    @Test
    void Java_입구에서_Kotlin_을_거쳐_Java_위험_지점까지_잇는다() throws IOException {
        write("app/src/main/AndroidManifest.xml", """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ex">
                    <application>
                        <activity android:name=".RunActivity" android:exported="true" />
                    </application>
                </manifest>
                """);
        write("app/src/main/java/com/ex/RunActivity.java", """
                package com.ex;

                import android.app.Activity;
                import android.os.Bundle;

                public class RunActivity extends Activity {
                    @Override
                    protected void onCreate(Bundle state) {
                        super.onCreate(state);
                        String cmd = getIntent().getStringExtra("cmd");
                        new CommandBridge().forward(cmd);
                    }
                }
                """);
        write("app/src/main/java/com/ex/CommandBridge.kt", """
                package com.ex

                class CommandBridge {
                    fun forward(cmd: String?) {
                        LegacyShell().exec(cmd ?: "")
                    }
                }
                """);
        write("app/src/main/java/com/ex/LegacyShell.java", """
                package com.ex;

                import java.io.IOException;

                public class LegacyShell {
                    public void exec(String cmd) {
                        try {
                            Runtime.getRuntime().exec(cmd);
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
                """);

        CodeGraph graph = CodeGraph.build(app, AndroidScanner.scan(app).scan());

        assertThat(graph.sinkPaths(10, 50)).anySatisfy(path -> assertThat(describe(path))
                .isEqualTo("ACTIVITY com.ex.RunActivity > com.ex.RunActivity#onCreate(Bundle) > com.ex.CommandBridge#forward(String) "
                        + "> com.ex.LegacyShell#exec(String) > COMMAND"));
    }

    private static String describe(SinkPath path) {
        StringBuilder sb = new StringBuilder();
        for (CodeGraph.Node node : path.path()) {
            if (!sb.isEmpty()) {
                sb.append(" > ");
            }
            sb.append(node.kind() == com.codeagent.core.model.CodeNodeKind.SINK ? node.prop("category") : node.qualifiedName());
        }
        return sb.toString();
    }

    private void write(String path, String content) throws IOException {
        Path file = app.resolve(path);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
