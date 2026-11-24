package com.sherlockphones.android;

import com.sherlockphones.android.AndroidManifests.Declared;
import com.sherlockphones.android.AndroidManifests.Manifest;
import com.sherlockphones.codegraph.StaticSink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AndroidManifestsTest {

    @TempDir
    Path root;

    @Test
    void exported_를_적지_않아도_인텐트_필터가_있으면_열린_것으로_보고_Provider_는_닫힌_것으로_본다() throws IOException {
        write("app/src/main/AndroidManifest.xml", """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.legacy">
                    <application>
                        <receiver android:name=".BootReceiver">
                            <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /></intent-filter>
                        </receiver>
                        <provider android:name="com.example.legacy.NotesProvider" android:authorities="notes" />
                        <provider android:name="Shared" android:authorities="shared" android:exported="true"
                            android:readPermission="com.example.READ" android:writePermission="com.example.WRITE" />
                        <activity-alias android:name=".Shortcut" android:targetActivity=".MainActivity" android:exported="true" />
                    </application>
                </manifest>
                """);
        List<String> errors = new ArrayList<>();
        Manifest manifest = AndroidManifests.load(root, errors).get(0);

        assertThat(errors).isEmpty();
        assertThat(manifest.namespace()).isEqualTo("com.example.legacy");
        Declared boot = manifest.components().get(0);
        assertThat(boot.className()).isEqualTo("com.example.legacy.BootReceiver");
        assertThat(boot.exported()).isTrue();
        assertThat(boot.implicitlyExported()).isTrue();
        Declared notes = manifest.components().get(1);
        assertThat(notes.exported()).isFalse();
        Declared shared = manifest.components().get(2);
        assertThat(shared.className()).isEqualTo("com.example.legacy.Shared");
        assertThat(shared.permissionProtected()).isTrue();
        assertThat(manifest.components().get(3).className()).isEqualTo("com.example.legacy.MainActivity");

        List<StaticSink> sinks = AndroidConfigChecks.check(root, manifest, errors);
        assertThat(sinks).extracting(StaticSink::category, StaticSink::line)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("EXPORTED", 3),
                        org.assertj.core.groups.Tuple.tuple("EXPORTED", 9));
        assertThat(sinks.get(0).api()).contains("인텐트 필터 때문에 열림");
    }

    @Test
    void 패키지가_없으면_build_gradle_의_namespace_를_쓰고_debug_매니페스트는_보지_않는다() throws IOException {
        write("app/build.gradle.kts", "android {\n    namespace = \"com.example.kts\"\n}\n");
        write("app/src/main/AndroidManifest.xml", """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application android:usesCleartextTraffic="true">
                        <activity android:name=".Main" android:exported="false" />
                    </application>
                </manifest>
                """);
        write("app/src/debug/AndroidManifest.xml", """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application android:debuggable="true" />
                </manifest>
                """);
        List<String> errors = new ArrayList<>();
        List<Manifest> manifests = AndroidManifests.load(root, errors);

        assertThat(manifests).extracting(Manifest::path).containsExactly("app/src/main/AndroidManifest.xml");
        assertThat(manifests.get(0).components().get(0).className()).isEqualTo("com.example.kts.Main");
        assertThat(AndroidConfigChecks.check(root, manifests.get(0), errors))
                .extracting(StaticSink::category).containsExactly("CLEARTEXT");
    }

    @Test
    void DOCTYPE_이_있는_XML_은_읽지_않는다() throws IOException {
        write("src/main/AndroidManifest.xml", """
                <?xml version="1.0"?>
                <!DOCTYPE manifest [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
                <manifest package="&xxe;"><application /></manifest>
                """);
        List<String> errors = new ArrayList<>();

        assertThat(AndroidManifests.load(root, errors)).isEmpty();
        assertThat(errors).singleElement().asString().contains("XML 을 읽지 못함");
    }

    private void write(String path, String content) throws IOException {
        Path file = root.resolve(path);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
