package io.camunda.connector.sandbox.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

/**
 * Result of a sandboxed CLI execution.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExecutionResult {

    /**
     * Unique execution ID for tracing
     */
    private String executionId;

    /**
     * Exit code from the command (0 = success)
     */
    private int exitCode;

    /**
     * Standard output from the command
     */
    private String stdout;

    /**
     * Standard error from the command
     */
    private String stderr;

    /**
     * Execution duration in milliseconds
     */
    private long durationMs;

    /**
     * Whether the execution was successful (exitCode == 0)
     */
    private boolean success;

    /**
     * Whether the execution was terminated due to timeout
     */
    private boolean timedOut;

    /**
     * Whether the execution was terminated due to resource limits
     */
    private boolean resourceLimitExceeded;

    /**
     * Resource usage statistics
     */
    private ResourceUsage resourceUsage;

    /**
     * Timestamp when execution started
     */
    private Instant startTime;

    /**
     * Timestamp when execution completed
     */
    private Instant endTime;

    /**
     * Error message if execution failed before command could run
     */
    private String errorMessage;

    /**
     * Convert to a map suitable for Zeebe output variables
     */
    public Map<String, Object> toOutputVariables() {
        return Map.of(
            "executionId", executionId != null ? executionId : "",
            "exitCode", exitCode,
            "stdout", stdout != null ? stdout : "",
            "stderr", stderr != null ? stderr : "",
            "durationMs", durationMs,
            "success", success,
            "timedOut", timedOut,
            "resourceLimitExceeded", resourceLimitExceeded,
            "errorMessage", errorMessage != null ? errorMessage : ""
        );
    }

    /**
     * Resource usage statistics from the execution
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceUsage {
        /**
         * Peak memory usage in bytes
         */
        private long peakMemoryBytes;

        /**
         * CPU time used in milliseconds
         */
        private long cpuTimeMs;

        /**
         * Number of bytes read from disk
         */
        private long bytesRead;

        /**
         * Number of bytes written to disk
         */
        private long bytesWritten;
    }

    /**
     * Create a successful result
     */
    public static ExecutionResult success(String executionId, String stdout, String stderr, long durationMs) {
        return ExecutionResult.builder()
                .executionId(executionId)
                .exitCode(0)
                .stdout(stdout)
                .stderr(stderr)
                .durationMs(durationMs)
                .success(true)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .build();
    }

    /**
     * Create a failed result
     */
    public static ExecutionResult failure(String executionId, int exitCode, String stdout, String stderr, 
                                           long durationMs, String errorMessage) {
        return ExecutionResult.builder()
                .executionId(executionId)
                .exitCode(exitCode)
                .stdout(stdout)
                .stderr(stderr)
                .durationMs(durationMs)
                .success(false)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .errorMessage(errorMessage)
                .build();
    }

    /**
     * Create a timeout result
     */
    public static ExecutionResult timeout(String executionId, String stdout, String stderr, long durationMs) {
        return ExecutionResult.builder()
                .executionId(executionId)
                .exitCode(-1)
                .stdout(stdout)
                .stderr(stderr)
                .durationMs(durationMs)
                .success(false)
                .timedOut(true)
                .resourceLimitExceeded(false)
                .errorMessage("Execution timed out")
                .build();
    }

    /**
     * Create a resource limit exceeded result
     */
    public static ExecutionResult resourceLimitExceeded(String executionId, String stdout, String stderr, 
                                                         long durationMs, String limitType) {
        return ExecutionResult.builder()
                .executionId(executionId)
                .exitCode(-1)
                .stdout(stdout)
                .stderr(stderr)
                .durationMs(durationMs)
                .success(false)
                .timedOut(false)
                .resourceLimitExceeded(true)
                .errorMessage("Resource limit exceeded: " + limitType)
                .build();
    }
}
