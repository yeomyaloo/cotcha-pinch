package com.sherlockphones.tools;

import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.Workspace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 에이전트가 자주 틀리는 인자를 한 번에 알려 주는지 (벤치마크 실행에서 실제로 막혔던 것들) */
class ToolArgsCheckTest {

    @TempDir
    Path home;

    @Test
    void 비슷한_이름의_인자를_알려_준다() {
        assertThatThrownBy(() -> call("submit_verdict", Map.of("app", "a", "finding", "F1", "verdict", "confirmed", "reasoning", "근거")))
                .isInstanceOf(ToolException.class)
                .hasMessageContaining("finding: 이 도구의 인자가 아님. finding_id 을(를) 말한 건가요?")
                .hasMessageContaining("finding_id: 꼭 넣어야 함")
                .hasMessageContaining("이 도구의 인자:")
                .hasMessageContaining("reasoning (필수)");
    }

    @Test
    void reason_은_reasoning_으로_받는다() {
        // 인자 검사는 통과하고, 등록하지 않은 앱이라서 그 다음 단계에서 멈춘다
        assertThatThrownBy(() -> call("submit_verdict", Map.of("app", "a", "finding_id", "F1", "verdict", "confirmed", "reason", "근거")))
                .isInstanceOf(ToolException.class)
                .message().doesNotContain("인자를 고쳐서").doesNotContain("reason: 이 도구의 인자가 아님");
        assertThat(ToolArgsCheck.normalize(Map.of("properties", Map.of("reasoning", Map.of())), Map.of("reason", "근거")))
                .isEqualTo(Map.of("reasoning", "근거"));
    }

    @Test
    void 모르는_인자를_조용히_무시하지_않는다() {
        // 예전에는 glob 을 무시하고 기본 대상에서 찾아 "일치하는 줄 없음" 을 돌려줬다
        assertThatThrownBy(() -> call("grep_code", Map.of("app", "a", "pattern", "token", "glob", "**.swift")))
                .hasMessageContaining("glob: 이 도구의 인자가 아님. file_glob 을(를) 말한 건가요?");
    }

    @Test
    void 배열_안_객체의_필드와_허용_값을_한_번에_알려_준다() {
        assertThatThrownBy(() -> call("record_finding", Map.of(
                "app", "a", "title", "t", "cwe", "CWE-89", "severity", "urgent", "attacker", "link", "description", "d",
                "evidence", List.of(Map.of("path", "A.swift", "line", "열둘")))))
                .hasMessageContaining("confidence: 꼭 넣어야 함")
                .hasMessageContaining("severity: [")
                .hasMessageContaining("(받은 값: urgent)")
                .hasMessageContaining("evidence[0].path: 이 도구의 인자가 아님")
                .hasMessageContaining("evidence[0].file: 꼭 넣어야 함")
                .hasMessageContaining("evidence[0].line: 정수여야 함")
                .hasMessageContaining("항목 예: {")
                .hasMessageContaining("\"file\": \"…\"")
                .hasMessageContaining("\"line\": 1");
    }

    @Test
    void 맞는_인자는_그대로_통과한다() {
        assertThat(ToolArgsCheck.closest("filePattern", List.of("app", "pattern", "file_glob"))).isEqualTo("pattern");
        assertThat(ToolArgsCheck.closest("zzz", List.of("app", "pattern"))).isNull();
        // 검사를 지나 도구 자체의 오류(앱 없음)가 나온다
        assertThatThrownBy(() -> call("list_findings", Map.of("app", "nothing")))
                .hasMessageNotContaining("인자를 고쳐서");
    }

    private String call(String name, Map<String, Object> args) {
        Workspace workspace = new Workspace(home, List.of("github.com"), 50L * 1024 * 1024, 30);
        SherlockTools tools = new SherlockTools(workspace, new AppRegistry(workspace), new FindingStore(workspace.findings()));
        ToolDef tool = tools.all().stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
        return tool.handler().apply(new Args(args));
    }
}
