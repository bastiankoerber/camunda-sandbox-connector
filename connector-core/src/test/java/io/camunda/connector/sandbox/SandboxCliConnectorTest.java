package io.camunda.connector.sandbox;

import io.camunda.connector.api.outbound.OutboundConnectorContext;
import io.camunda.connector.sandbox.audit.AuditLogger;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.execution.ExecutionOrchestrator;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.security.SecurityValidator;
import io.camunda.connector.sandbox.tenant.TenantContextExtractor;
import io.camunda.connector.sandbox.tools.ToolRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for SandboxCliConnector.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SandboxCliConnector")
class SandboxCliConnectorTest {

    @Mock
    private SecurityValidator securityValidator;

    @Mock
    private ExecutionOrchestrator executionOrchestrator;

    @Mock
    private TenantContextExtractor tenantContextExtractor;

    @Mock
    private AuditLogger auditLogger;

    @Mock
    private SandboxConfig config;

    @Mock
    private ToolRegistry toolRegistry;

    @Mock
    private OutboundConnectorContext context;

    private SandboxCliConnector connector;

    @BeforeEach
    void setUp() {
        connector = new SandboxCliConnector(
                securityValidator,
                executionOrchestrator,
                tenantContextExtractor,
                auditLogger,
                config,
                toolRegistry
        );
    }

    @Nested
    @DisplayName("Successful execution")
    class SuccessfulExecution {

        @Test
        @DisplayName("should execute simple command successfully")
        void shouldExecuteSimpleCommand() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.name'")
                    .allowedTools(List.of("jq"))
                    .timeoutSeconds("30")
                    .memoryLimitMb("256")
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "test-output", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            Object result = connector.execute(context);

            // Then
            assertThat(result).isInstanceOf(Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(true);
            assertThat(resultMap.get("stdout")).isEqualTo("test-output");
            assertThat(resultMap.get("exitCode")).isEqualTo(0);

            verify(securityValidator).validate(request);
            verify(auditLogger).logExecution(anyString(), eq(request), eq(expectedResult));
        }

        @Test
        @DisplayName("should use tenant from request")
        void shouldUseTenantFromRequest() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("curl -s https://api.example.com")
                    .allowedTools(List.of("curl"))
                    .tenantId("production")
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "{\"data\": \"test\"}", "", 500L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("production");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(tenantContextExtractor).extractTenantId(context, request);
            assertThat(request.getTenantId()).isEqualTo("production");
        }

        @Test
        @DisplayName("should pass environment variables to execution")
        void shouldPassEnvironmentVariables() throws Exception {
            // Given
            Map<String, String> envVars = Map.of("API_KEY", "secret123");
            SandboxRequest request = SandboxRequest.builder()
                    .command("curl -s $API_URL")
                    .allowedTools(List.of("curl"))
                    .environment(envVars)
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "ok", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req -> 
                    req.getEnvironment() != null && 
                    req.getEnvironment().get("API_KEY").equals("secret123")), anyString());
        }
    }

    @Nested
    @DisplayName("Security validation")
    class SecurityValidation {

        @Test
        @DisplayName("should reject command that fails security validation")
        void shouldRejectFailedSecurityValidation() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("rm -rf /")
                    .allowedTools(List.of("rm"))
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            doThrow(new SecurityException("Dangerous command detected"))
                    .when(securityValidator).validate(any());

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Dangerous command detected");

            verify(auditLogger).logSecurityViolation(anyString(), any(SecurityException.class));
            verify(executionOrchestrator, never()).execute(any(), anyString());
        }

        @Test
        @DisplayName("should reject command with shell operators")
        void shouldRejectShellOperators() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("cat /etc/passwd | grep root")
                    .allowedTools(List.of("cat", "grep"))
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            doThrow(new SecurityException("Shell operators not allowed"))
                    .when(securityValidator).validate(any());

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(SecurityException.class);

            verify(auditLogger).logSecurityViolation(anyString(), any());
        }
    }

    @Nested
    @DisplayName("Execution failures")
    class ExecutionFailures {

        @Test
        @DisplayName("should handle execution timeout")
        void shouldHandleExecutionTimeout() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("sleep 100")
                    .allowedTools(List.of("sleep"))
                    .timeoutSeconds("1")
                    .build();

            ExecutionResult timeoutResult = ExecutionResult.timeout("exec-123", "", "", 1000L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(timeoutResult);

            // When
            Object result = connector.execute(context);

            // Then
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(false);
            assertThat(resultMap.get("timedOut")).isEqualTo(true);
        }

        @Test
        @DisplayName("should handle command failure")
        void shouldHandleCommandFailure() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("false")
                    .allowedTools(List.of("false"))
                    .build();

            ExecutionResult failureResult = ExecutionResult.failure(
                    "exec-123", 1, "", "Command failed", 50L, "Exit code 1");

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(failureResult);

            // When
            Object result = connector.execute(context);

            // Then
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(false);
            assertThat(resultMap.get("exitCode")).isEqualTo(1);
        }

        @Test
        @DisplayName("should log errors on execution failure")
        void shouldLogErrorsOnFailure() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.name'")
                    .allowedTools(List.of("jq"))
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString()))
                    .thenThrow(new RuntimeException("Sandbox creation failed"));

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(RuntimeException.class);

            verify(auditLogger).logError(anyString(), any(Exception.class));
        }
    }

    @Nested
    @DisplayName("Resource limits")
    class ResourceLimits {

        @Test
        @DisplayName("should pass resource limits to orchestrator")
        void shouldPassResourceLimits() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.'")
                    .allowedTools(List.of("jq"))
                    .timeoutSeconds("60")
                    .memoryLimitMb("512")
                    .cpuLimitMillis(2000)
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req ->
                    req.getTimeoutSecondsInt() == 60 &&
                    req.getMemoryLimitMbInt() == 512 &&
                    req.getCpuLimitMillis() == 2000
            ), anyString());
        }

        @Test
        @DisplayName("should handle resource limit exceeded")
        void shouldHandleResourceLimitExceeded() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("memory-hog")
                    .allowedTools(List.of("memory-hog"))
                    .memoryLimitMb("64")
                    .build();

            ExecutionResult resourceResult = ExecutionResult.resourceLimitExceeded(
                    "exec-123", "", "Out of memory", 500L, "memory");

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(resourceResult);

            // When
            Object result = connector.execute(context);

            // Then
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(false);
            assertThat(resultMap.get("resourceLimitExceeded")).isEqualTo(true);
        }
    }

    @Nested
    @DisplayName("Network access modes")
    class NetworkAccessModes {

        @Test
        @DisplayName("should support NONE network access")
        void shouldSupportNoneNetwork() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.'")
                    .allowedTools(List.of("jq"))
                    .networkAccess(SandboxRequest.NetworkAccess.NONE)
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req ->
                    req.getNetworkAccess() == SandboxRequest.NetworkAccess.NONE
            ), anyString());
        }

        @Test
        @DisplayName("should support RESTRICTED network access")
        void shouldSupportRestrictedNetwork() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("curl https://api.github.com")
                    .allowedTools(List.of("curl"))
                    .networkAccess(SandboxRequest.NetworkAccess.RESTRICTED)
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 500L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req ->
                    req.getNetworkAccess() == SandboxRequest.NetworkAccess.RESTRICTED
            ), anyString());
        }
    }

    @Nested
    @DisplayName("Multi-tool commands")
    class MultiToolCommands {

        @Test
        @DisplayName("should allow multiple tools in allowedTools list")
        void shouldAllowMultipleTools() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("curl -s https://api.example.com")
                    .allowedTools(List.of("curl", "jq", "grep"))
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "{}", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req ->
                    req.getAllowedTools().size() == 3
            ), anyString());
        }
    }

    @Nested
    @DisplayName("Script mode execution")
    class ScriptModeExecution {

        @Test
        @DisplayName("should execute script content successfully")
        void shouldExecuteScriptContent() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("import json\nprint(json.dumps({'key': 'value'}))")
                    .scriptLanguage("python")
                    .allowedTools(List.of("safe-python3"))
                    .timeoutSeconds("30")
                    .memoryLimitMb("256")
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "{\"key\": \"value\"}", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            Object result = connector.execute(context);

            // Then
            assertThat(result).isInstanceOf(Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(true);
            assertThat(resultMap.get("stdout")).isEqualTo("{\"key\": \"value\"}");

            verify(securityValidator).validate(request);
            verify(executionOrchestrator).execute(argThat(req ->
                    req.hasScriptContent() &&
                    req.getScriptContent().contains("import json")
            ), anyString());
        }

        @Test
        @DisplayName("should execute script without command field")
        void shouldExecuteScriptWithoutCommand() throws Exception {
            // Given - script mode without command field (the bug we fixed)
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("print('hello world')")
                    .scriptLanguage("python")
                    .allowedTools(List.of("safe-python3"))
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "hello world", "", 50L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            Object result = connector.execute(context);

            // Then - should NOT throw "Command cannot be empty"
            assertThat(result).isInstanceOf(Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(true);

            // Verify security validation was called (it should handle script mode)
            verify(securityValidator).validate(request);
        }

        @Test
        @DisplayName("should use safe-python3 as the tool for script execution")
        void shouldUseSafePython3ForScripts() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("import math\nprint(math.pi)")
                    .scriptLanguage("python")
                    .allowedTools(List.of("safe-python3"))
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "3.141592653589793", "", 100L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then
            verify(executionOrchestrator).execute(argThat(req ->
                    req.getAllowedTools().contains("safe-python3")
            ), anyString());
        }

        @Test
        @DisplayName("should support multi-line Python scripts")
        void shouldSupportMultiLineScripts() throws Exception {
            // Given - multi-line script like the one in the BPMN
            String multiLineScript = """
                import json
                import math
                import statistics
                
                users = [
                    dict(name='Alice', age=28, score=85.5),
                    dict(name='Bob', age=34, score=92.0)
                ]
                
                ages = [u['age'] for u in users]
                result = dict(mean_age=statistics.mean(ages))
                print(json.dumps(result))
                """;

            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent(multiLineScript)
                    .scriptLanguage("python")
                    .allowedTools(List.of("safe-python3"))
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success(
                    "exec-123", "{\"mean_age\": 31.0}", "", 200L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            Object result = connector.execute(context);

            // Then
            assertThat(result).isInstanceOf(Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) result;
            assertThat(resultMap.get("success")).isEqualTo(true);
        }

        @Test
        @DisplayName("should use default tenant for script execution")
        void shouldUseDefaultTenantForScripts() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("print('hello')")
                    .scriptLanguage("python")
                    .allowedTools(List.of("safe-python3"))
                    .build();

            ExecutionResult expectedResult = ExecutionResult.success("exec-123", "hello", "", 50L);

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            when(executionOrchestrator.execute(any(), anyString())).thenReturn(expectedResult);

            // When
            connector.execute(context);

            // Then - verify default tenant is used and safe-python3 is allowed
            verify(tenantContextExtractor).extractTenantId(context, request);
            assertThat(request.getTenantId()).isEqualTo("default");
        }

        @Test
        @DisplayName("should reject script when safe-python3 not in allowed tools")
        void shouldRejectScriptWhenToolNotAllowed() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("print('hello')")
                    .scriptLanguage("python")
                    .allowedTools(List.of("jq"))  // safe-python3 NOT in list
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);
            when(tenantContextExtractor.extractTenantId(any(), any())).thenReturn("default");
            doThrow(new SecurityException("Tool 'safe-python3' is not allowed"))
                    .when(securityValidator).validate(any());

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }

        @Test
        @DisplayName("should reject unsupported script language")
        void shouldRejectUnsupportedScriptLanguage() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .scriptContent("console.log('hello')")
                    .scriptLanguage("javascript")
                    .allowedTools(List.of("safe-python3"))
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("javascript");
        }

        @Test
        @DisplayName("should reject both command and scriptContent")
        void shouldRejectBothCommandAndScript() throws Exception {
            // Given
            SandboxRequest request = SandboxRequest.builder()
                    .command("jq '.'")
                    .scriptContent("print('hello')")
                    .allowedTools(List.of("jq", "safe-python3"))
                    .build();

            when(context.bindVariables(SandboxRequest.class)).thenReturn(request);

            // When/Then
            assertThatThrownBy(() -> connector.execute(context))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Cannot specify both");
        }
    }
}
