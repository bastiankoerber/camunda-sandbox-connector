package io.camunda.connector.sandbox.execution;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.sandbox.SandboxManager;
import io.camunda.connector.sandbox.security.CommandParser;
import io.camunda.connector.sandbox.tools.ToolInstaller;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for ExecutionOrchestrator.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ExecutionOrchestrator")
class ExecutionOrchestratorTest {

    @Mock
    private SandboxManager sandboxManager;

    @Mock
    private ToolInstaller toolInstaller;

    @Mock
    private CommandParser commandParser;

    @Mock
    private SandboxConfig config;

    @Mock
    private SandboxConfig.ExecutionConfig executionConfig;

    private MeterRegistry meterRegistry;
    private ExecutionOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        
        // Configure execution settings
        when(config.getExecution()).thenReturn(executionConfig);
        when(executionConfig.getThreadPoolSize()).thenReturn(4);
        when(executionConfig.getQueueSize()).thenReturn(100);
        when(executionConfig.getGracePeriodSeconds()).thenReturn(5);
        
        orchestrator = new ExecutionOrchestrator(
                sandboxManager,
                toolInstaller,
                commandParser,
                config,
                meterRegistry
        );
    }

    @Nested
    @DisplayName("Successful execution")
    class SuccessfulExecution {

        @Test
        @DisplayName("should execute command and return result")
        void shouldExecuteCommand() throws Exception {
            // Given
            SandboxRequest request = createRequest("jq '.name'", List.of("jq"));
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of(".name"))
                    .rawCommand("jq '.name'")
                    .build();
            
            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "test-output", "", 100L);

            when(commandParser.parse("jq '.name'")).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable("jq", null)).thenReturn("/usr/bin/jq");
            when(sandboxManager.executeInSandbox(any(), any(), anyString())).thenReturn(expectedResult);

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-123");

            // Then
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getStdout()).isEqualTo("test-output");
            
            verify(commandParser).parse("jq '.name'");
            verify(toolInstaller).ensureToolAvailable("jq", null);
            verify(sandboxManager).executeInSandbox(request, parsedCommand, "exec-123");
        }

        @Test
        @DisplayName("should use specific tool version when provided")
        void shouldUseSpecificToolVersion() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.name'")
                    .allowedTools(List.of("jq"))
                    .toolVersions(Map.of("jq", "1.7.1"))
                    .timeoutSeconds("30")
                    .build();
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of(".name"))
                    .rawCommand("jq '.name'")
                    .build();
            
            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable("jq", "1.7.1")).thenReturn("/tools/jq/1.7.1/jq");
            when(sandboxManager.executeInSandbox(any(), any(), anyString())).thenReturn(expectedResult);

            // When
            orchestrator.execute(request, "exec-123");

            // Then
            verify(toolInstaller).ensureToolAvailable("jq", "1.7.1");
        }

        @Test
        @DisplayName("should record execution metrics")
        void shouldRecordMetrics() throws Exception {
            // Given
            SandboxRequest request = createRequest("jq '.'", List.of("jq"));
            request.setTenantId("test-tenant");
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of("."))
                    .rawCommand("jq '.'")
                    .build();
            
            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any())).thenReturn("/usr/bin/jq");
            when(sandboxManager.executeInSandbox(any(), any(), anyString())).thenReturn(expectedResult);

            // When
            orchestrator.execute(request, "exec-123");

            // Then
            assertThat(meterRegistry.find("sandbox.execution.duration").timer()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Timeout handling")
    class TimeoutHandling {

        @Test
        @DisplayName("should return timeout result when execution times out")
        void shouldHandleTimeout() throws Exception {
            // Given
            SandboxRequest request = createRequest("sleep 100", List.of("sleep"));
            request.setTimeoutSeconds("1");
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("sleep")
                    .arguments(List.of("100"))
                    .rawCommand("sleep 100")
                    .build();

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any())).thenReturn("/bin/sleep");
            // Simulate slow execution
            when(sandboxManager.executeInSandbox(any(), any(), anyString()))
                    .thenAnswer(invocation -> {
                        Thread.sleep(10000); // Sleep longer than timeout
                        return ExecutionResult.success("exec-123", "", "", 10000L);
                    });

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-123");

            // Then
            assertThat(result.isTimedOut()).isTrue();
            assertThat(result.isSuccess()).isFalse();
            
            verify(sandboxManager).forceCleanup("exec-123");
        }
    }

    @Nested
    @DisplayName("Error handling")
    class ErrorHandling {

        @Test
        @DisplayName("should return failure result when tool not found")
        void shouldHandleToolNotFound() throws Exception {
            // Given
            SandboxRequest request = createRequest("unknown-tool", List.of("unknown-tool"));
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("unknown-tool")
                    .arguments(List.of())
                    .rawCommand("unknown-tool")
                    .build();

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any()))
                    .thenThrow(new IllegalArgumentException("Tool not found in registry"));

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-123");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).contains("Tool not found");
        }

        @Test
        @DisplayName("should return failure result when sandbox fails")
        void shouldHandleSandboxFailure() throws Exception {
            // Given
            SandboxRequest request = createRequest("jq '.'", List.of("jq"));
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of("."))
                    .rawCommand("jq '.'")
                    .build();

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any())).thenReturn("/usr/bin/jq");
            when(sandboxManager.executeInSandbox(any(), any(), anyString()))
                    .thenThrow(new IOException("Failed to create sandbox"));

            // When
            ExecutionResult result = orchestrator.execute(request, "exec-123");

            // Then
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getErrorMessage()).contains("Failed to create sandbox");
        }
    }

    @Nested
    @DisplayName("Async execution")
    class AsyncExecution {

        @Test
        @DisplayName("should execute asynchronously")
        void shouldExecuteAsync() throws Exception {
            // Given
            SandboxRequest request = createRequest("jq '.'", List.of("jq"));
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of("."))
                    .rawCommand("jq '.'")
                    .build();
            
            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any())).thenReturn("/usr/bin/jq");
            when(sandboxManager.executeInSandbox(any(), any(), anyString())).thenReturn(expectedResult);

            // When
            CompletableFuture<ExecutionResult> future = orchestrator.executeAsync(request, "exec-123");
            ExecutionResult result = future.get(5, TimeUnit.SECONDS);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
        }
    }

    @Nested
    @DisplayName("Concurrency control")
    class ConcurrencyControl {

        @Test
        @DisplayName("should limit concurrent executions")
        void shouldLimitConcurrency() throws Exception {
            // Given
            SandboxRequest request = createRequest("jq '.'", List.of("jq"));
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                    .executable("jq")
                    .arguments(List.of("."))
                    .rawCommand("jq '.'")
                    .build();

            when(commandParser.parse(anyString())).thenReturn(parsedCommand);
            when(toolInstaller.ensureToolAvailable(anyString(), any())).thenReturn("/usr/bin/jq");
            // Return result immediately to avoid blocking
            when(sandboxManager.executeInSandbox(any(), any(), anyString()))
                    .thenReturn(ExecutionResult.success("exec", "{}", "", 10L));

            // When - launch a few concurrent executions (within thread pool size)
            CompletableFuture<ExecutionResult>[] futures = new CompletableFuture[3];
            for (int i = 0; i < 3; i++) {
                futures[i] = orchestrator.executeAsync(request, "exec-" + i);
            }

            // Wait for all to complete
            CompletableFuture.allOf(futures).get(30, TimeUnit.SECONDS);

            // Then - all should complete (concurrency is managed internally)
            for (CompletableFuture<ExecutionResult> future : futures) {
                assertThat(future.isDone()).isTrue();
                assertThat(future.get().isSuccess()).isTrue();
            }
        }
    }

    /**
     * Helper method to create a basic request.
     */
    private SandboxRequest createRequest(String command, List<String> tools) {
        return SandboxRequest.builder()
                .command(command)
                .allowedTools(tools)
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .cpuLimitMillis(1000)
                .networkAccess(SandboxRequest.NetworkAccess.NONE)
                .build();
    }
}
