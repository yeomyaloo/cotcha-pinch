package com.sherlockphones;

import com.sherlockphones.findings.FindingStore;
import com.sherlockphones.tools.Args;
import com.sherlockphones.tools.SherlockTools;
import com.sherlockphones.tools.ToolDef;
import com.sherlockphones.tools.ToolException;
import com.sherlockphones.workspace.AppRegistry;
import com.sherlockphones.workspace.Workspace;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncPromptSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.Prompt;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import io.modelcontextprotocol.spec.McpSchema.Role;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * stdio MCP 서버. Claude Code, Claude Desktop 같은 채팅 클라이언트가 이 프로세스를 띄우고 표준 입출력으로 대화한다.
 * 표준 출력은 MCP 메시지 전용이라 로그는 표준 오류로만 쓴다.
 */
public final class SherlockPhones {

    private static final Logger log = LoggerFactory.getLogger(SherlockPhones.class);
    static final String VERSION = "0.9.7";

    private SherlockPhones() {
    }

    public static void main(String[] args) {
        Workspace workspace = Workspace.fromEnvironment();
        SherlockTools tools = new SherlockTools(workspace, new AppRegistry(workspace), new FindingStore(workspace.findings()));

        var server = McpServer.sync(new StdioServerTransportProvider(McpJsonDefaults.getMapper()))
                .serverInfo("cotcha-pinch", VERSION)
                .instructions(Prompts.INSTRUCTIONS)
                .capabilities(ServerCapabilities.builder().tools(true).prompts(true).build())
                .tools(tools.all().stream().map(SherlockPhones::toolSpec).toList())
                .prompts(prompts())
                .build();
        log.info("cotcha-pinch {} 시작 (작업 폴더 {})", VERSION, workspace.home());
        // stdio 전송은 백그라운드 스레드에서 돈다. 클라이언트가 입력을 닫으면 프로세스가 끝난다
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
    }

    static SyncToolSpecification toolSpec(ToolDef def) {
        Tool tool = Tool.builder()
                .name(def.name())
                .title(def.title())
                .description(def.description())
                .inputSchema(def.inputSchema())
                .annotations(new ToolAnnotations(def.title(), def.readOnly(), false, def.readOnly(), def.openWorld(), null))
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> call(def, request.arguments()))
                .build();
    }

    /** 도구를 실행한다. 입력 오류는 Claude 가 고쳐서 다시 부를 수 있게 isError 결과로 돌려준다 */
    static CallToolResult call(ToolDef def, Map<String, Object> arguments) {
        try {
            return CallToolResult.builder().addTextContent(def.handler().apply(new Args(arguments))).isError(false).build();
        } catch (ToolException e) {
            return CallToolResult.builder().addTextContent("오류: " + e.getMessage()).isError(true).build();
        } catch (RuntimeException e) {
            log.warn("도구 실행 실패: {} {}", def.name(), arguments, e);
            return CallToolResult.builder().addTextContent("도구 실행 실패: " + e).isError(true).build();
        }
    }

    static List<SyncPromptSpecification> prompts() {
        Prompt audit = new Prompt("mobile_audit", "모바일 앱 보안 분석",
                "앱을 불러와 외부에 열린 입구 → 위험 지점과 설정을 조사하고, 발견을 다시 검증한 뒤 보고서를 만든다",
                List.of(new PromptArgument("target", "분석할 앱 폴더 경로 또는 공개 Git https 주소", true),
                        new PromptArgument("max_items", "조사할 항목 수 (기본 12)", false)));
        Prompt verify = new Prompt("verify_findings", "발견 다시 검증",
                "검증 대기 중인 발견을 반대 입장에서 다시 확인해 판정한다",
                List.of(new PromptArgument("app", "앱 id", true)));
        return List.of(
                new SyncPromptSpecification(audit, (exchange, request) -> {
                    Map<String, Object> a = request.arguments() == null ? Map.of() : request.arguments();
                    String target = String.valueOf(a.getOrDefault("target", "")).strip();
                    String maxItems = String.valueOf(a.getOrDefault("max_items", "12")).strip();
                    return message("모바일 앱 보안 분석: " + target, Prompts.mobileAudit(target, maxItems.isEmpty() ? "12" : maxItems));
                }),
                new SyncPromptSpecification(verify, (exchange, request) -> {
                    Map<String, Object> a = request.arguments() == null ? Map.of() : request.arguments();
                    String app = String.valueOf(a.getOrDefault("app", "")).strip();
                    return message("발견 다시 검증: " + app, Prompts.verifyFindings(app));
                }));
    }

    private static GetPromptResult message(String description, String text) {
        return new GetPromptResult(description, List.of(new PromptMessage(Role.USER, new TextContent(text))));
    }
}
