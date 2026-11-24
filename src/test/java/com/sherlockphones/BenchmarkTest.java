package com.sherlockphones;

import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.tools.Args;
import com.sherlockphones.tools.SherlockTools;
import com.sherlockphones.tools.ToolDef;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.Workspace;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 평가 벤치마크(benchmark/)의 정해진 부분. LLM 없이 도구 결과만 본다.
 * 앱마다 정답의 취약점과 함정이 모두 위험 지점으로 나오고(조사 대상에 오르고) 그 밖의 것은 없으며,
 * 입구가 있는 취약점은 list_sink_paths 에도 나오는지 확인한다. LLM 의 판단은 benchmark/score.py 로 따로 잰다.
 */
class BenchmarkTest {

    /** 안드로이드 벤치마크 앱 (다른 테스트도 쓴다) */
    static final Path APP = Path.of("benchmark/bank-app").toAbsolutePath();
    private static final Pattern SINK_LINE = Pattern.compile("\\[([A-Z_]+) CWE-\\d+\\].* · (\\S+:\\d+)$");

    @TempDir
    Path home;

    @ParameterizedTest
    @ValueSource(strings = {"bank-app", "bank-ios"})
    void 정답의_취약점과_함정이_모두_위험_지점으로_나오고_다른_것은_없다(String app) throws IOException {
        SherlockTools tools = load(app);
        JsonNode expected = expected(app);
        List<String> answer = new ArrayList<>();
        expected.path("vulnerabilities").forEach(i -> answer.add(key(i)));
        expected.path("safe").forEach(i -> answer.add(key(i)));

        List<String> sinks = new ArrayList<>();
        for (String line : call(tools, "list_sinks", Map.of("app", app)).split("\n")) {
            Matcher m = SINK_LINE.matcher(line.strip());
            if (m.find()) {
                sinks.add(m.group(2) + " " + m.group(1));
            }
        }

        assertThat(sinks).containsExactlyInAnyOrderElementsOf(answer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bank-app", "bank-ios"})
    void 입구가_있는_취약점은_경로로도_나온다(String app) throws IOException {
        SherlockTools tools = load(app);
        String paths = call(tools, "list_sink_paths", Map.of("app", app));
        for (JsonNode vuln : expected(app).path("vulnerabilities")) {
            if (!vuln.path("entryPoint").isNull()) {
                assertThat(paths).as(vuln.path("id").asString())
                        .contains(vuln.path("entryPoint").asString() + "  →  [" + vuln.path("category").asString());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"bank-app", "bank-ios"})
    void 정답_파일이_올바르고_앱_폴더_밖에_있다(String app) throws IOException {
        Path root = Path.of("benchmark", app).toAbsolutePath();
        JsonNode expected = expected(app);
        List<String> ids = new ArrayList<>();
        List<JsonNode> items = new ArrayList<>();
        expected.path("vulnerabilities").forEach(items::add);
        expected.path("safe").forEach(items::add);
        for (JsonNode item : items) {
            String id = item.path("id").asString();
            assertThat(ids).as("id 중복").doesNotContain(id);
            ids.add(id);
            assertThat(root.resolve(item.path("file").asString())).as(id).isRegularFile();
            assertThat(item.path("sinkLine").asInt()).as(id)
                    .isBetween(item.path("lines").get(0).asInt(), item.path("lines").get(1).asInt());
        }
        for (JsonNode vuln : expected.path("vulnerabilities")) {
            assertThat(vuln.path("cwe").isArray() && !vuln.path("cwe").isEmpty()).as(vuln.path("id").asString()).isTrue();
            assertThat(vuln.path("attacker").asString()).isIn("other_app", "link", "network", "device");
        }
        // 에이전트가 분석하다 정답을 읽지 못하게 한다
        try (var files = Files.walk(root)) {
            assertThat(files.map(p -> p.getFileName().toString())).noneMatch(n -> n.endsWith(".expected.json"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private SherlockTools load(String app) {
        Workspace workspace = new Workspace(home, List.of("github.com"), 50L * 1024 * 1024, 30);
        SherlockTools tools = new SherlockTools(workspace, new AppRegistry(workspace), new FindingStore(workspace.findings()));
        call(tools, "load_app", Map.of("path", Path.of("benchmark", app).toAbsolutePath().toString()));
        return tools;
    }

    private static JsonNode expected(String app) throws IOException {
        return JsonMapper.builder().build().readTree(Files.readString(Path.of("benchmark", app + ".expected.json")));
    }

    private static String key(JsonNode item) {
        return item.path("file").asString() + ":" + item.path("sinkLine").asInt() + " " + item.path("category").asString();
    }

    private static String call(SherlockTools tools, String name, Map<String, Object> args) {
        ToolDef tool = tools.all().stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
        return tool.handler().apply(new Args(args));
    }
}
