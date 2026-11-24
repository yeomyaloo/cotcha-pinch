package com.sherlockphones.workspace;

import com.sherlockphones.android.AndroidScanner;
import com.sherlockphones.android.AndroidScanner.AndroidApp;
import com.sherlockphones.codegraph.CodeGraph;
import com.sherlockphones.source.GitCloner;
import com.sherlockphones.source.GitCloner.CloneResult;
import com.sherlockphones.source.GitRevision;
import com.sherlockphones.source.GitUrlPolicy;
import com.sherlockphones.tools.ToolException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 이 서버 프로세스가 불러온 앱 목록. 코드 그래프는 메모리에만 있고, 서버를 다시 켜면 다시 불러온다.
 */
public class AppRegistry {

    private final Workspace workspace;
    private final GitUrlPolicy gitUrlPolicy;
    private final GitCloner gitCloner;
    private final Map<String, LoadedApp> repositories = new LinkedHashMap<>();

    public AppRegistry(Workspace workspace) {
        this(workspace, new GitUrlPolicy(workspace.gitHosts()));
    }

    public AppRegistry(Workspace workspace, GitUrlPolicy gitUrlPolicy) {
        this.workspace = workspace;
        this.gitUrlPolicy = gitUrlPolicy;
        this.gitCloner = new GitCloner(workspace.cloneTimeoutSeconds(), workspace.maxRepoBytes());
    }

    /** 로컬 폴더를 불러온다. 같은 이름이 있으면 다시 파싱해서 바꾼다 */
    public synchronized LoadedApp loadLocal(String path, String name) {
        Path root = Path.of(path).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            throw new ToolException("폴더가 아님: " + root);
        }
        String id = idFor(name != null ? name : root.getFileName().toString());
        // 폴더에 .git 이 있으면 HEAD 커밋을 기록한다 (발견·라이브러리 검사에 어느 커밋이었는지 남김)
        String commit = GitRevision.head(root).orElse(null);
        return put(analyze(id, root, null, null, commit));
    }

    /** 공개 Git 저장소를 얕게 클론해서 불러온다. 이미 받은 저장소면 최신 커밋으로 다시 받는다 */
    public synchronized LoadedApp loadGit(String gitUrl, String branch, String name) {
        String url;
        try {
            url = gitUrlPolicy.validate(gitUrl);
        } catch (IllegalArgumentException e) {
            throw new ToolException(e.getMessage());
        }
        String id = idFor(name != null ? name : GitUrlPolicy.repoName(url));
        Path target = workspace.repos().resolve(id);
        GitCloner.deleteQuietly(target);
        try {
            Files.createDirectories(target.getParent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        CloneResult clone;
        try {
            clone = gitCloner.cloneInto(url, branch, target);
        } catch (IllegalArgumentException e) {
            throw new ToolException(e.getMessage());
        }
        return put(analyze(id, target, url, clone.branch(), clone.commitSha()));
    }

    public synchronized LoadedApp get(String id) {
        LoadedApp repository = repositories.get(id);
        if (repository == null) {
            throw new ToolException("불러온 앱이 아님: " + id + ". load_app 을 먼저 호출할 것"
                    + (repositories.isEmpty() ? "" : " (불러온 앱: " + String.join(", ", repositories.keySet()) + ")"));
        }
        return repository;
    }

    public synchronized Collection<LoadedApp> all() {
        return repositories.values().stream().toList();
    }

    /** 매니페스트·설정·줄 단위 규칙으로 플랫폼 재료를 만들고, Java 소스와 합쳐 코드 그래프를 만든다 */
    private static LoadedApp analyze(String id, Path root, String gitUrl, String branch, String commit) {
        AndroidApp android = AndroidScanner.scan(root);
        return new LoadedApp(id, root, gitUrl, branch, commit, CodeGraph.build(root, android.scan()), android, OffsetDateTime.now());
    }

    private LoadedApp put(LoadedApp repository) {
        repositories.put(repository.id(), repository);
        return repository;
    }

    /** 도구 인자로 쓰기 쉬운 이름으로 바꾼다 (영문 소문자, 숫자, . _ -) */
    static String idFor(String name) {
        String id = name.strip().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]+", "-").replaceAll("^-+|-+$", "");
        if (id.isEmpty() || id.equals(".") || id.equals("..")) {
            throw new ToolException("앱 이름으로 쓸 수 없음: " + name);
        }
        return id;
    }
}
