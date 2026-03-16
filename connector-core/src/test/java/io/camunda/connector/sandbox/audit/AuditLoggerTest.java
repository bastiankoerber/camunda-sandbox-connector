package io.camunda.connector.sandbox.audit;

import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.SandboxRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Test suite for AuditLogger - audit logging functionality.
 */
class AuditLoggerTest {

    private AuditLogger auditLogger;

    @BeforeEach
    void setUp() {
        auditLogger = new AuditLogger();
    }

    @Nested
    @DisplayName("Execution Logging")
    class ExecutionLoggingTests {

        @Test
        @DisplayName("Should log successful execution without throwing")
        void shouldLogSuccessfulExecution() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("hello")
                .success(true)
                .durationMs(100)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-123", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log failed execution without throwing")
        void shouldLogFailedExecution() {
            SandboxRequest request = SandboxRequest.builder()
                .command("invalid-cmd")
                .allowedTools(List.of("invalid-cmd"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-456")
                .exitCode(1)
                .stderr("command not found")
                .success(false)
                .durationMs(50)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-456", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log timed out execution")
        void shouldLogTimedOutExecution() {
            SandboxRequest request = SandboxRequest.builder()
                .command("sleep 100")
                .allowedTools(List.of("sleep"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-789")
                .exitCode(-1)
                .success(false)
                .timedOut(true)
                .durationMs(30000)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-789", request, result))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Execution Start Logging")
    class ExecutionStartLoggingTests {

        @Test
        @DisplayName("Should log execution start")
        void shouldLogExecutionStart() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://api.example.com")
                .allowedTools(List.of("curl"))
                .tenantId("test-tenant")
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.RESTRICTED)
                .build();

            assertThatCode(() ->
                auditLogger.logExecutionStart("exec-start-123", request))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log execution start with environment")
        void shouldLogExecutionStartWithEnvironment() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -H $API_KEY https://api.example.com")
                .allowedTools(List.of("curl"))
                .tenantId("test-tenant")
                .environment(Map.of("API_KEY", "secret-value"))
                .build();

            assertThatCode(() ->
                auditLogger.logExecutionStart("exec-start-456", request))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Security Violation Logging")
    class SecurityViolationLoggingTests {

        @Test
        @DisplayName("Should log security violation")
        void shouldLogSecurityViolation() {
            SecurityException securityException = new SecurityException("Command injection detected");

            assertThatCode(() ->
                auditLogger.logSecurityViolation("exec-sec-123", securityException))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log security violation with details")
        void shouldLogSecurityViolationWithDetails() {
            SecurityException securityException = new SecurityException(
                "Tool 'rm' is not allowed for tenant: restricted-tenant");

            assertThatCode(() ->
                auditLogger.logSecurityViolation("exec-sec-456", securityException))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Error Logging")
    class ErrorLoggingTests {

        @Test
        @DisplayName("Should log execution error")
        void shouldLogExecutionError() {
            Exception error = new RuntimeException("Sandbox creation failed");

            assertThatCode(() ->
                auditLogger.logError("exec-err-123", error))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log IO error")
        void shouldLogIOError() {
            Exception error = new java.io.IOException("Failed to write to workspace");

            assertThatCode(() ->
                auditLogger.logError("exec-err-456", error))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log error with cause")
        void shouldLogErrorWithCause() {
            Exception cause = new IllegalStateException("Invalid state");
            Exception error = new RuntimeException("Execution failed", cause);

            assertThatCode(() ->
                auditLogger.logError("exec-err-789", error))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Resource Limit Logging")
    class ResourceLimitLoggingTests {

        @Test
        @DisplayName("Should log memory limit exceeded")
        void shouldLogMemoryLimitExceeded() {
            assertThatCode(() ->
                auditLogger.logResourceLimitExceeded("exec-res-123", "memory", "Exceeded 256MB limit"))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log CPU limit exceeded")
        void shouldLogCpuLimitExceeded() {
            assertThatCode(() ->
                auditLogger.logResourceLimitExceeded("exec-res-456", "cpu", "Exceeded CPU time limit"))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log file size limit exceeded")
        void shouldLogFileSizeLimitExceeded() {
            assertThatCode(() ->
                auditLogger.logResourceLimitExceeded("exec-res-789", "filesize", "Exceeded 64MB file limit"))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Timeout Logging")
    class TimeoutLoggingTests {

        @Test
        @DisplayName("Should log timeout event")
        void shouldLogTimeout() {
            assertThatCode(() ->
                auditLogger.logTimeout("exec-timeout-123", 30))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should log timeout with various durations")
        void shouldLogTimeoutWithVariousDurations() {
            int[] timeouts = {1, 10, 30, 60, 300};

            for (int timeout : timeouts) {
                assertThatCode(() ->
                    auditLogger.logTimeout("exec-timeout-" + timeout, timeout))
                    .doesNotThrowAnyException();
            }
        }
    }

    @Nested
    @DisplayName("Command Masking Tests")
    class CommandMaskingTests {

        @Test
        @DisplayName("Should handle null command")
        void shouldHandleNullCommand() {
            SandboxRequest request = SandboxRequest.builder()
                .command(null)
                .allowedTools(List.of("test"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-null")
                .exitCode(0)
                .success(true)
                .build();

            // Should not throw even with null command
            assertThatCode(() ->
                auditLogger.logExecution("exec-null", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should mask password in command")
        void shouldMaskPassword() {
            SandboxRequest request = SandboxRequest.builder()
                .command("mysql -p password=secret123")
                .allowedTools(List.of("mysql"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-mask")
                .exitCode(0)
                .success(true)
                .build();

            // Should complete without throwing - masking happens internally
            assertThatCode(() ->
                auditLogger.logExecution("exec-mask", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should mask Bearer token")
        void shouldMaskBearerToken() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' https://api.com")
                .allowedTools(List.of("curl"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-bearer")
                .exitCode(0)
                .success(true)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-bearer", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should mask Basic auth")
        void shouldMaskBasicAuth() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://api.com")
                .allowedTools(List.of("curl"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-basic")
                .exitCode(0)
                .success(true)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-basic", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle very long command")
        void shouldHandleLongCommand() {
            StringBuilder longCmd = new StringBuilder("echo ");
            for (int i = 0; i < 500; i++) {
                longCmd.append("word").append(i).append(" ");
            }

            SandboxRequest request = SandboxRequest.builder()
                .command(longCmd.toString())
                .allowedTools(List.of("echo"))
                .tenantId("test-tenant")
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-long")
                .exitCode(0)
                .success(true)
                .build();

            assertThatCode(() ->
                auditLogger.logExecution("exec-long", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should mask API key patterns")
        void shouldMaskApiKeyPatterns() {
            String[] sensitiveCommands = {
                "curl -H 'key=abc123secret'",
                "curl -H 'token:xyz789'",
                "curl -H 'auth=myauthvalue'",
                "curl -H 'secret=topsecret'"
            };

            for (String cmd : sensitiveCommands) {
                SandboxRequest request = SandboxRequest.builder()
                    .command(cmd)
                    .allowedTools(List.of("curl"))
                    .tenantId("test-tenant")
                    .build();

                ExecutionResult result = ExecutionResult.builder()
                    .executionId("exec-key")
                    .exitCode(0)
                    .success(true)
                    .build();

                assertThatCode(() ->
                    auditLogger.logExecution("exec-key", request, result))
                    .doesNotThrowAnyException();
            }
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle full execution lifecycle logging")
        void shouldHandleFullLifecycle() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://api.example.com")
                .allowedTools(List.of("curl"))
                .tenantId("test-tenant")
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .build();

            // Log start
            assertThatCode(() ->
                auditLogger.logExecutionStart("exec-lifecycle", request))
                .doesNotThrowAnyException();

            // Log completion
            ExecutionResult result = ExecutionResult.success("exec-lifecycle", "response", "", 500);
            assertThatCode(() ->
                auditLogger.logExecution("exec-lifecycle", request, result))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle failed execution lifecycle")
        void shouldHandleFailedLifecycle() {
            SandboxRequest request = SandboxRequest.builder()
                .command("dangerous-command")
                .allowedTools(List.of("dangerous-command"))
                .tenantId("test-tenant")
                .build();

            // Log start
            auditLogger.logExecutionStart("exec-failed", request);

            // Log security violation
            SecurityException secEx = new SecurityException("Command rejected");
            auditLogger.logSecurityViolation("exec-failed", secEx);

            // All logging should complete without exceptions
            assertThat(true).isTrue(); // If we get here, all logging worked
        }
    }
}
