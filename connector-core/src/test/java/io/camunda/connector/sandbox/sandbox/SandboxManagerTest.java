package io.camunda.connector.sandbox.sandbox;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.tenant.PolicyLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for SandboxManager - sandbox lifecycle and execution.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SandboxManagerTest {

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

    private SandboxManager sandboxManager;

    @BeforeEach
    void setUp() {
        // Set up common config mocks
        when(config.getSecurity()).thenReturn(securityConfig);
        when(config.getExecution()).thenReturn(executionConfig);
        when(config.getNsjailPath()).thenReturn("/usr/bin/nsjail");
        when(config.getSandboxRootfs()).thenReturn("/sandbox/rootfs");
        when(config.getToolsDirectory()).thenReturn("/sandbox/tools");
        when(config.getWorkspacePath(anyString())).thenAnswer(
            invocation -> tempDir.resolve("workspace-" + invocation.getArgument(0)));
        when(config.getSeccompProfilePath(anyString())).thenReturn(tempDir.resolve("seccomp.json"));
        when(securityConfig.getDefaultSeccompProfile()).thenReturn("default");
        when(securityConfig.isUseUserNamespace()).thenReturn(true);
        when(securityConfig.isUsePidNamespace()).thenReturn(true);
        when(securityConfig.isUseMountNamespace()).thenReturn(true);
        when(securityConfig.getSandboxUid()).thenReturn(65534);
        when(securityConfig.getSandboxGid()).thenReturn(65534);
        when(executionConfig.getMaxOutputBytes()).thenReturn(1048576);

        sandboxManager = new SandboxManager(config, policyLoader);
    }

    @Nested
    @DisplayName("SandboxManager Construction")
    class ConstructionTests {

        @Test
        @DisplayName("Should create sandbox manager with valid config")
        void shouldCreateWithValidConfig() {
            assertThat(sandboxManager).isNotNull();
        }

        @Test
        @DisplayName("Should initialize with config dependencies")
        void shouldInitializeWithDependencies() {
            // Verify the manager was created without errors
            SandboxManager manager = new SandboxManager(config, policyLoader);
            assertThat(manager).isNotNull();
        }
    }

    @Nested
    @DisplayName("Force Cleanup Tests")
    class ForceCleanupTests {

        @Test
        @DisplayName("Should handle cleanup for non-existent execution ID")
        void shouldHandleCleanupForNonExistentExecution() {
            // Should not throw when cleaning up non-existent execution
            assertThatCode(() -> sandboxManager.forceCleanup("non-existent-id"))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should clean up workspace directory during cleanup")
        void shouldCleanUpWorkspaceDirectory() throws Exception {
            String executionId = "cleanup-test-123";
            Path workspacePath = tempDir.resolve("workspace-" + executionId);
            
            // Create workspace directory
            java.nio.file.Files.createDirectories(workspacePath);
            java.nio.file.Files.writeString(workspacePath.resolve("test.txt"), "test content");
            
            // Force cleanup
            sandboxManager.forceCleanup(executionId);
            
            // Workspace should be cleaned up
            assertThat(workspacePath).doesNotExist();
        }
    }

    @Nested
    @DisplayName("Request Validation Tests")
    class RequestValidationTests {

        @Test
        @DisplayName("Should create valid sandbox request")
        void shouldCreateValidRequest() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.NONE)
                .build();

            assertThat(request.getCommand()).isEqualTo("echo hello");
            assertThat(request.getAllowedTools()).contains("echo");
            assertThat(request.getTimeoutSeconds()).isEqualTo("30");
        }

        @Test
        @DisplayName("Should handle request with environment variables")
        void shouldHandleEnvironmentVariables() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo $VAR")
                .allowedTools(List.of("echo"))
                .environment(Map.of("VAR", "value"))
                .build();

            assertThat(request.getEnvironment()).containsEntry("VAR", "value");
        }

        @Test
        @DisplayName("Should handle request with network access modes")
        void shouldHandleNetworkAccessModes() {
            for (SandboxRequest.NetworkAccess mode : SandboxRequest.NetworkAccess.values()) {
                SandboxRequest request = SandboxRequest.builder()
                    .command("test")
                    .allowedTools(List.of("test"))
                    .networkAccess(mode)
                    .build();

                assertThat(request.getNetworkAccess()).isEqualTo(mode);
            }
        }
    }

    @Nested
    @DisplayName("Parsed Command Tests")
    class ParsedCommandTests {

        @Test
        @DisplayName("Should convert parsed command to command list")
        void shouldConvertToCommandList() {
            ParsedCommand parsed = ParsedCommand.builder()
                .executable("curl")
                .arguments(List.of("-s", "https://example.com"))
                .build();

            List<String> cmdList = parsed.toCommandList();
            assertThat(cmdList).containsExactly("curl", "-s", "https://example.com");
        }

        @Test
        @DisplayName("Should handle parsed command with no arguments")
        void shouldHandleNoArguments() {
            ParsedCommand parsed = ParsedCommand.builder()
                .executable("ls")
                .arguments(List.of())
                .build();

            List<String> cmdList = parsed.toCommandList();
            assertThat(cmdList).containsExactly("ls");
        }
    }

    @Nested
    @DisplayName("Execution Result Factory Methods")
    class ExecutionResultFactoryTests {

        @Test
        @DisplayName("Should create success result")
        void shouldCreateSuccessResult() {
            ExecutionResult result = ExecutionResult.success("exec-123", "output", "", 1000);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getExitCode()).isEqualTo(0);
            assertThat(result.getStdout()).isEqualTo("output");
            assertThat(result.isTimedOut()).isFalse();
        }

        @Test
        @DisplayName("Should create timeout result")
        void shouldCreateTimeoutResult() {
            ExecutionResult result = ExecutionResult.timeout("exec-123", "partial", "", 30000);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.isTimedOut()).isTrue();
            assertThat(result.getExitCode()).isEqualTo(-1);
            assertThat(result.getErrorMessage()).contains("timed out");
        }

        @Test
        @DisplayName("Should create failure result")
        void shouldCreateFailureResult() {
            ExecutionResult result = ExecutionResult.failure(
                "exec-123", 1, "", "error message", 500, "Command failed");

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getExitCode()).isEqualTo(1);
            assertThat(result.getErrorMessage()).isEqualTo("Command failed");
        }

        @Test
        @DisplayName("Should create resource limit exceeded result")
        void shouldCreateResourceLimitResult() {
            ExecutionResult result = ExecutionResult.resourceLimitExceeded(
                "exec-123", "", "OOM", 1000, "memory");

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.isResourceLimitExceeded()).isTrue();
            assertThat(result.getErrorMessage()).contains("memory");
        }
    }

    @Nested
    @DisplayName("Output Variable Conversion Tests")
    class OutputVariableTests {

        @Test
        @DisplayName("Should convert result to output variables")
        void shouldConvertToOutputVariables() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("hello world")
                .stderr("")
                .durationMs(500)
                .success(true)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .build();

            Map<String, Object> vars = result.toOutputVariables();

            assertThat(vars).containsEntry("executionId", "exec-123");
            assertThat(vars).containsEntry("exitCode", 0);
            assertThat(vars).containsEntry("stdout", "hello world");
            assertThat(vars).containsEntry("success", true);
        }

        @Test
        @DisplayName("Should handle null values in output variables")
        void shouldHandleNullValues() {
            ExecutionResult result = ExecutionResult.builder()
                .exitCode(0)
                .success(true)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .build();

            Map<String, Object> vars = result.toOutputVariables();

            assertThat(vars).containsEntry("executionId", "");
            assertThat(vars).containsEntry("stdout", "");
            assertThat(vars).containsEntry("stderr", "");
            assertThat(vars).containsEntry("errorMessage", "");
        }
    }

    @Nested
    @DisplayName("Workspace Management Tests")
    class WorkspaceTests {

        @Test
        @DisplayName("Should generate unique workspace paths")
        void shouldGenerateUniqueWorkspacePaths() {
            when(config.getWorkspacePath("exec-1")).thenReturn(tempDir.resolve("ws-1"));
            when(config.getWorkspacePath("exec-2")).thenReturn(tempDir.resolve("ws-2"));

            Path path1 = config.getWorkspacePath("exec-1");
            Path path2 = config.getWorkspacePath("exec-2");

            assertThat(path1).isNotEqualTo(path2);
        }
    }

    @Nested
    @DisplayName("Resource Usage Tests")
    class ResourceUsageTests {

        @Test
        @DisplayName("Should create resource usage statistics")
        void shouldCreateResourceUsage() {
            ExecutionResult.ResourceUsage usage = ExecutionResult.ResourceUsage.builder()
                .peakMemoryBytes(1024 * 1024 * 100) // 100 MB
                .cpuTimeMs(500)
                .bytesRead(1000)
                .bytesWritten(2000)
                .build();

            assertThat(usage.getPeakMemoryBytes()).isEqualTo(104857600);
            assertThat(usage.getCpuTimeMs()).isEqualTo(500);
            assertThat(usage.getBytesRead()).isEqualTo(1000);
            assertThat(usage.getBytesWritten()).isEqualTo(2000);
        }

        @Test
        @DisplayName("Should include resource usage in result")
        void shouldIncludeResourceUsageInResult() {
            ExecutionResult.ResourceUsage usage = ExecutionResult.ResourceUsage.builder()
                .peakMemoryBytes(50000000)
                .cpuTimeMs(250)
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .success(true)
                .resourceUsage(usage)
                .build();

            assertThat(result.getResourceUsage()).isNotNull();
            assertThat(result.getResourceUsage().getPeakMemoryBytes()).isEqualTo(50000000);
        }
    }
}
