package com.sherlockphones.workspace;

import com.sherlockphones.android.AndroidScanner.AndroidApp;
import com.sherlockphones.codegraph.CodeGraph;
import com.sherlockphones.ios.IosScanner.IosApp;

import java.nio.file.Path;
import java.time.OffsetDateTime;

/**
 * 분석하려고 불러온 앱과 그 코드 그래프.
 *
 * @param id      도구에서 앱을 가리키는 이름 (예: bank-app)
 * @param gitUrl  로컬 폴더에서 불러왔으면 null
 * @param android 매니페스트와 안드로이드 검사 재료 (안드로이드 앱이 아니면 매니페스트가 비어 있다)
 * @param ios     Info.plist·entitlements 와 iOS 검사 재료 (iOS 앱이 아니면 비어 있다)
 */
public record LoadedApp(String id, Path root, String gitUrl, String branch, String commitSha,
                        CodeGraph graph, AndroidApp android, IosApp ios, OffsetDateTime loadedAt) {

    public String origin() {
        if (gitUrl == null) {
            return commitSha == null ? root.toString() : root + " @ " + commitSha.substring(0, Math.min(12, commitSha.length()));
        }
        return gitUrl + " (" + branch + " @ " + commitSha.substring(0, Math.min(12, commitSha.length())) + ")";
    }
}
