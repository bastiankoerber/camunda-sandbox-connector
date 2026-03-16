package io.camunda.connector.sandbox.audit;

import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.SandboxRequest;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.argument.StructuredArguments;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Audit logger for sandbox executions.
 * Provides structured logging for security auditing and compliance.
 */
@Slf4j
@Component
public class AuditLogger {

    private static final String AUDIT_EVENT = "SANDBOX_AUDIT";

    /**
     * Log a successful execution.
     */
    public void logExecution(String executionId, SandboxRequest request, ExecutionResult result) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "EXECUTION_COMPLETED");
        auditData.put("executionId", executionId);
        auditData.put("tenantId", request.getTenantId());
        auditData.put("command", maskCommand(request.getEffectiveCommand()));
        auditData.put("allowedTools", request.getAllowedTools());
        auditData.put("exitCode", result.getExitCode());
        auditData.put("success", result.isSuccess());
        auditData.put("durationMs", result.getDurationMs());
        auditData.put("timedOut", result.isTimedOut());
        auditData.put("timestamp", Instant.now().toString());

        if (result.isSuccess()) {
            log.info("{} - Execution completed successfully",
                    AUDIT_EVENT,
                    StructuredArguments.entries(auditData));
        } else {
            log.warn("{} - Execution completed with failure",
                    AUDIT_EVENT,
                    StructuredArguments.entries(auditData));
        }
    }

    /**
     * Log a security violation.
     */
    public void logSecurityViolation(String executionId, SecurityException exception) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "SECURITY_VIOLATION");
        auditData.put("executionId", executionId);
        auditData.put("violationType", exception.getClass().getSimpleName());
        auditData.put("message", exception.getMessage());
        auditData.put("timestamp", Instant.now().toString());

        log.error("{} - Security violation detected",
                AUDIT_EVENT,
                StructuredArguments.entries(auditData));
    }

    /**
     * Log an execution error.
     */
    public void logError(String executionId, Exception exception) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "EXECUTION_ERROR");
        auditData.put("executionId", executionId);
        auditData.put("errorType", exception.getClass().getSimpleName());
        auditData.put("message", exception.getMessage());
        auditData.put("timestamp", Instant.now().toString());

        log.error("{} - Execution error occurred",
                AUDIT_EVENT,
                StructuredArguments.entries(auditData));
    }

    /**
     * Log when execution starts.
     */
    public void logExecutionStart(String executionId, SandboxRequest request) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "EXECUTION_STARTED");
        auditData.put("executionId", executionId);
        auditData.put("tenantId", request.getTenantId());
        auditData.put("command", maskCommand(request.getEffectiveCommand()));
        auditData.put("allowedTools", request.getAllowedTools());
        auditData.put("timeoutSeconds", request.getTimeoutSecondsInt());
        auditData.put("memoryLimitMb", request.getMemoryLimitMbInt());
        auditData.put("networkAccess", request.getNetworkAccess());
        auditData.put("timestamp", Instant.now().toString());

        log.info("{} - Execution started",
                AUDIT_EVENT,
                StructuredArguments.entries(auditData));
    }

    /**
     * Log resource limit exceeded.
     */
    public void logResourceLimitExceeded(String executionId, String limitType, String details) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "RESOURCE_LIMIT_EXCEEDED");
        auditData.put("executionId", executionId);
        auditData.put("limitType", limitType);
        auditData.put("details", details);
        auditData.put("timestamp", Instant.now().toString());

        log.warn("{} - Resource limit exceeded",
                AUDIT_EVENT,
                StructuredArguments.entries(auditData));
    }

    /**
     * Log timeout event.
     */
    public void logTimeout(String executionId, int timeoutSeconds) {
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("event", "EXECUTION_TIMEOUT");
        auditData.put("executionId", executionId);
        auditData.put("timeoutSeconds", timeoutSeconds);
        auditData.put("timestamp", Instant.now().toString());

        log.warn("{} - Execution timed out",
                AUDIT_EVENT,
                StructuredArguments.entries(auditData));
    }

    /**
     * Mask sensitive parts of the command for logging.
     */
    private String maskCommand(String command) {
        if (command == null) {
            return "[null]";
        }

        // Mask potential secrets
        String masked = command;
        masked = masked.replaceAll("(password|token|key|secret|auth)[=:][^\\s]+", "$1=***");
        masked = masked.replaceAll("Bearer [^\\s]+", "Bearer ***");
        masked = masked.replaceAll("Basic [^\\s]+", "Basic ***");

        // Truncate if too long
        if (masked.length() > 200) {
            masked = masked.substring(0, 200) + "...";
        }

        return masked;
    }
}
