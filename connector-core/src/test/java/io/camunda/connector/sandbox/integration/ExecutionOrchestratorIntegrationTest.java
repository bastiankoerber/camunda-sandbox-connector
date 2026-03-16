package io.camunda.connector.sandbox.integration;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.execution.ExecutionOrchestrator;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.model.ToolDefinition;
import io.camunda.connector.sandbox.sandbox.SandboxManager;
import io.camunda.connector.sandbox.security.CommandParser;
import io.camunda.connector.sandbox.tenant.PolicyLoader;
import io.camunda.connector.sandbox.tools.ToolInstaller;
import io.camunda.connector.sandbox.tools.ToolRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Integration tests for ExecutionOrchestrator.
 * 
 * These tests use REAL implementations of CommandParser, ToolInstaller, and ToolRegistry,
 * but MOCK the SandboxManager to verify the correct data flows between components.
 * 
 * CRITICAL: These tests catch wiring bugs that unit tests with mocked dependencies miss.
 * 
 * The key bug these tests catch:
 * - ExecutionOrchestrator must pass the RESOLVED binary path (e.g., "/bin/curl") to SandboxManager,
 *   not just the tool name (e.g., "curl"). If this fails, nsjail can't find the binary.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ExecutionOrchestrator Integration Tests")
class ExecutionOrchestratorIntegrationTest {

    @Mock
    private SandboxConfig config;

    @Mock
    private SandboxConfig.SecurityConfig securityConfig;

    @Mock
    private SandboxConfig.ExecutionConfig executionConfig;

    @Mock
    private PolicyLoader policyLoader;

    @TempDir
    Path tempDir;

    // Real implementations - NOT mocked
    private CommandParser commandParser;
    private ToolRegistry toolRegistry;
    private ToolInstaller toolInstaller;

    // Spied to capture arguments passed to it
    private SandboxManager sandboxManager;

    private ExecutionOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        // Configure the mocked config
        when(config.getSecurity()).thenReturn(securityConfig);
        when(config.getExecution()).thenReturn(executionConfig);
        when(config.getNsjailPath()).thenReturn("/usr/bin/nsjail");
        when(config.getSandboxRootfs()).thenReturn("/sandbox/rootfs");
        when(config.getToolsDirectory()).thenReturn(tempDir.resolve("tools").toString());
        when(config.getToolRegistryPath()).thenReturn(null); // Use classpath registry
        when(config.getWorkspacePath(anyString())).thenAnswer(
            invocation -> tempDir.resolve("workspace-" + invocation.getArgument(0)));
        when(config.getToolPath(anyString(), anyString())).thenAnswer(
            invocation -> tempDir.resolve("tools/" + invocation.getArgument(0) + "/" + invocation.getArgument(1)));

        when(securityConfig.isUseUserNamespace()).thenReturn(true);
        when(securityConfig.isUsePidNamespace()).thenReturn(true);
        when(securityConfig.isUseMountNamespace()).thenReturn(true);
        when(securityConfig.getSandboxUid()).thenReturn(65534);
        when(securityConfig.getSandboxGid()).thenReturn(65534);

        when(executionConfig.getThreadPoolSize()).thenReturn(4);
        when(executionConfig.getQueueSize()).thenReturn(100);
        when(executionConfig.getGracePeriodSeconds()).thenReturn(5);
        when(executionConfig.getMaxOutputBytes()).thenReturn(1048576);

        // Create REAL implementations
        commandParser = new CommandParser();
        toolRegistry = new ToolRegistry(config);
        
        // Register built-in tools with absolute paths
        registerTestTools();
        
        toolInstaller = new ToolInstaller(config, toolRegistry);

        // Create a REAL SandboxManager but SPY on it to capture arguments
        SandboxManager realSandboxManager = new SandboxManager(config, policyLoader);
        sandboxManager = spy(realSandboxManager);

        // Mock the actual sandbox execution (we don't want to run nsjail in tests)
        try {
            doReturn(ExecutionResult.success("test-exec", "output", "", 100L))
                .when(sandboxManager).executeInSandbox(any(), any(), anyString());
        } catch (Exception e) {
            throw new RuntimeException("Failed to setup mock", e);
        }

        orchestrator = new ExecutionOrchestrator(
            sandboxManager,
            toolInstaller,
            commandParser,
            config,
            new SimpleMeterRegistry()
        );
    }

    /**
     * Register test tools with known binary paths.
     * These paths must match what's in the sandbox rootfs.
     */
    private void registerTestTools() {
        toolRegistry.registerTool(ToolDefinition.builder()
            .name("curl")
            .displayName("curl")
            .description("Command line tool for transferring data with URLs")
            .version("latest")
            .category("utility")
            .installMethod("SYSTEM")
            .binaryPath("/bin/curl")  // CRITICAL: This is the path inside the sandbox
            .networkAccess(true)
            .seccompProfile("network")
            .build());

        toolRegistry.registerTool(ToolDefinition.builder()
            .name("jq")
            .displayName("jq")
            .description("Command-line JSON processor")
            .version("latest")
            .category("utility")
            .installMethod("SYSTEM")
            .binaryPath("/bin/jq")
            .networkAccess(false)
            .seccompProfile("strict")
            .build());

        toolRegistry.registerTool(ToolDefinition.builder()
            .name("git")
            .displayName("git")
            .description("Distributed version control system")
            .version("latest")
            .category("utility")
            .installMethod("SYSTEM")
            .binaryPath("/bin/git")
            .networkAccess(true)
            .seccompProfile("network")
            .build());
    }

    @Nested
    @DisplayName("Tool Path Resolution Tests")
    class ToolPathResolutionTests {

        /**
         * CRITICAL TEST: Verifies that the resolved binary path is passed to SandboxManager.
         * 
         * This test would have FAILED before the fix in ExecutionOrchestrator line 119:
         *   parsedCommand.setExecutable(toolPath);
         * 
         * Without that fix, SandboxManager received "curl" instead of "/bin/curl",
         * causing nsjail to fail with "process:'curl' ... exited with status: 255"
         */
        @Test
        @DisplayName("Should pass resolved binary path to SandboxManager for curl")
        void shouldPassResolvedBinaryPathForCurl() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -s https://example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.FULL)
                .build();

            // When
            orchestrator.execute(request, "exec-curl-test");

            // Then - capture the ParsedCommand passed to SandboxManager
            ArgumentCaptor<ParsedCommand> commandCaptor = ArgumentCaptor.forClass(ParsedCommand.class);
            verify(sandboxManager).executeInSandbox(any(), commandCaptor.capture(), anyString());

            ParsedCommand capturedCommand = commandCaptor.getValue();
            
            // CRITICAL ASSERTION: The executable must be the FULL PATH, not just "curl"
            assertThat(capturedCommand.getExecutable())
                .withFailMessage(
                    "Expected executable to be '/bin/curl' but got '%s'. " +
                    "This means ExecutionOrchestrator is not updating the ParsedCommand with the resolved tool path. " +
                    "nsjail requires absolute paths inside the chroot.",
                    capturedCommand.getExecutable())
                .isEqualTo("/bin/curl");

            // Arguments should be preserved
            assertThat(capturedCommand.getArguments())
                .containsExactly("-s", "https://example.com");
        }

        @Test
        @DisplayName("Should pass resolved binary path to SandboxManager for jq")
        void shouldPassResolvedBinaryPathForJq() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("jq -r '.name'")
                .allowedTools(List.of("jq"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.NONE)
                .build();

            // When
            orchestrator.execute(request, "exec-jq-test");

            // Then
            ArgumentCaptor<ParsedCommand> commandCaptor = ArgumentCaptor.forClass(ParsedCommand.class);
            verify(sandboxManager).executeInSandbox(any(), commandCaptor.capture(), anyString());

            ParsedCommand capturedCommand = commandCaptor.getValue();
            
            assertThat(capturedCommand.getExecutable())
                .withFailMessage(
                    "Expected executable to be '/bin/jq' but got '%s'",
                    capturedCommand.getExecutable())
                .isEqualTo("/bin/jq");

            assertThat(capturedCommand.getArguments())
                .containsExactly("-r", ".name");
        }

        @Test
        @DisplayName("Should pass resolved binary path to SandboxManager for git")
        void shouldPassResolvedBinaryPathForGit() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("git status")
                .allowedTools(List.of("git"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.NONE)
                .build();

            // When
            orchestrator.execute(request, "exec-git-test");

            // Then
            ArgumentCaptor<ParsedCommand> commandCaptor = ArgumentCaptor.forClass(ParsedCommand.class);
            verify(sandboxManager).executeInSandbox(any(), commandCaptor.capture(), anyString());

            ParsedCommand capturedCommand = commandCaptor.getValue();
            
            assertThat(capturedCommand.getExecutable())
                .withFailMessage(
                    "Expected executable to be '/bin/git' but got '%s'",
                    capturedCommand.getExecutable())
                .isEqualTo("/bin/git");
        }

        /**
         * Verifies that all built-in tools use absolute paths starting with /bin/.
         * This catches registry.yaml misconfigurations.
         */
        @Test
        @DisplayName("All registered tools should have absolute binary paths")
        void allToolsShouldHaveAbsoluteBinaryPaths() {
            toolRegistry.getAllTools().forEach((name, tool) -> {
                String binaryPath = tool.getBinaryPath();
                
                assertThat(binaryPath)
                    .withFailMessage(
                        "Tool '%s' has binaryPath '%s' which is not an absolute path. " +
                        "All tools must have absolute paths for nsjail to find them in the chroot.",
                        name, binaryPath)
                    .startsWith("/");

                // Verify it's in a standard location
                assertThat(binaryPath)
                    .withFailMessage(
                        "Tool '%s' has binaryPath '%s' which is not in /bin/. " +
                        "The sandbox rootfs has binaries in /bin/, not /usr/bin/ or elsewhere.",
                        name, binaryPath)
                    .startsWith("/bin/");
            });
        }
    }

    @Nested
    @DisplayName("Command Parsing Integration Tests")
    class CommandParsingIntegrationTests {

        @Test
        @DisplayName("Should preserve complex jq filter arguments")
        void shouldPreserveComplexJqFilterArguments() throws Exception {
            // Given - jq filter with pipe operator inside quotes (allowed)
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.data | .items[] | select(.active == true)'")
                .allowedTools(List.of("jq"))
                .timeoutSeconds("30")
                .build();

            // When
            orchestrator.execute(request, "exec-jq-complex");

            // Then
            ArgumentCaptor<ParsedCommand> commandCaptor = ArgumentCaptor.forClass(ParsedCommand.class);
            verify(sandboxManager).executeInSandbox(any(), commandCaptor.capture(), anyString());

            ParsedCommand capturedCommand = commandCaptor.getValue();
            
            assertThat(capturedCommand.getExecutable()).isEqualTo("/bin/jq");
            // The filter should be preserved as a single argument (quotes removed)
            assertThat(capturedCommand.getArguments())
                .containsExactly(".data | .items[] | select(.active == true)");
        }

        @Test
        @DisplayName("Should handle multiple arguments correctly")
        void shouldHandleMultipleArgumentsCorrectly() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -s -H 'Content-Type: application/json' -X POST https://api.example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("30")
                .networkAccess(SandboxRequest.NetworkAccess.FULL)
                .build();

            // When
            orchestrator.execute(request, "exec-curl-complex");

            // Then
            ArgumentCaptor<ParsedCommand> commandCaptor = ArgumentCaptor.forClass(ParsedCommand.class);
            verify(sandboxManager).executeInSandbox(any(), commandCaptor.capture(), anyString());

            ParsedCommand capturedCommand = commandCaptor.getValue();
            
            assertThat(capturedCommand.getExecutable()).isEqualTo("/bin/curl");
            assertThat(capturedCommand.getArguments())
                .containsExactly("-s", "-H", "Content-Type: application/json", "-X", "POST", "https://api.example.com");
        }
    }

    @Nested
    @DisplayName("Error Handling Integration Tests")
    class ErrorHandlingIntegrationTests {

        @Test
        @DisplayName("Should return failure when tool is not in registry")
        void shouldReturnFailureForUnknownTool() {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("unknown-tool --help")
                .allowedTools(List.of("unknown-tool"))
                .timeoutSeconds("30")
                .build();

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-unknown");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).contains("not found");

            // SandboxManager should NOT have been called
            try {
                verify(sandboxManager, never()).executeInSandbox(any(), any(), anyString());
            } catch (Exception e) {
                // Ignore - this is just for verification
            }
        }

        @Test
        @DisplayName("Should return failure when sandbox execution fails")
        void shouldReturnFailureWhenSandboxFails() throws Exception {
            // Given
            doThrow(new IOException("Sandbox creation failed"))
                .when(sandboxManager).executeInSandbox(any(), any(), anyString());

            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("30")
                .networkAccess(SandboxRequest.NetworkAccess.FULL)
                .build();

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-fail");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).contains("Sandbox");
        }
    }

    @Nested
    @DisplayName("Request Validation Integration Tests")
    class RequestValidationIntegrationTests {

        @Test
        @DisplayName("Should reject commands with shell operators")
        void shouldRejectCommandsWithShellOperators() {
            // Given - pipe operator outside quotes
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com | jq '.name'")
                .allowedTools(List.of("curl", "jq"))
                .timeoutSeconds("30")
                .build();

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-pipe");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).containsIgnoringCase("shell");
        }

        @Test
        @DisplayName("Should reject direct shell invocation")
        void shouldRejectDirectShellInvocation() {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                .command("bash -c 'echo hello'")
                .allowedTools(List.of("bash"))
                .timeoutSeconds("30")
                .build();

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-shell");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).containsIgnoringCase("shell");
        }
    }
}
