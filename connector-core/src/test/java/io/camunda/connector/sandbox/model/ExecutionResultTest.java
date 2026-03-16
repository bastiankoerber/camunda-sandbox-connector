package io.camunda.connector.sandbox.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Test suite for ExecutionResult - result building and factory methods.
 */
class ExecutionResultTest {

    @Nested
    @DisplayName("Result Building")
    class ResultBuildingTests {

        @Test
        @DisplayName("Should build result with all fields")
        void shouldBuildWithAllFields() {
            Instant start = Instant.now();
            Instant end = start.plusSeconds(5);

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("output text")
                .stderr("error text")
                .durationMs(5000)
                .success(true)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .startTime(start)
                .endTime(end)
                .errorMessage(null)
                .build();

            assertThat(result.getExecutionId()).isEqualTo("exec-123");
            assertThat(result.getExitCode()).isEqualTo(0);
            assertThat(result.getStdout()).isEqualTo("output text");
            assertThat(result.getStderr()).isEqualTo("error text");
            assertThat(result.getDurationMs()).isEqualTo(5000);
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.isTimedOut()).isFalse();
            assertThat(result.isResourceLimitExceeded()).isFalse();
            assertThat(result.getStartTime()).isEqualTo(start);
            assertThat(result.getEndTime()).isEqualTo(end);
        }

        @Test
        @DisplayName("Should handle minimal result")
        void shouldHandleMinimalResult() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("min-123")
                .exitCode(0)
                .success(true)
                .build();

            assertThat(result.getExecutionId()).isEqualTo("min-123");
            assertThat(result.isSuccess()).isTrue();
        }
    }

    @Nested
    @DisplayName("Factory Methods")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should create success result")
        void shouldCreateSuccessResult() {
            ExecutionResult result = ExecutionResult.success(
                "exec-success", "hello world", "", 1000);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getExitCode()).isEqualTo(0);
            assertThat(result.getStdout()).isEqualTo("hello world");
            assertThat(result.getStderr()).isEmpty();
            assertThat(result.getDurationMs()).isEqualTo(1000);
            assertThat(result.isTimedOut()).isFalse();
            assertThat(result.isResourceLimitExceeded()).isFalse();
        }

        @Test
        @DisplayName("Should create failure result")
        void shouldCreateFailureResult() {
            ExecutionResult result = ExecutionResult.failure(
                "exec-fail", 127, "", "command not found", 500, "Command failed");

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getExitCode()).isEqualTo(127);
            assertThat(result.getStderr()).isEqualTo("command not found");
            assertThat(result.getErrorMessage()).isEqualTo("Command failed");
            assertThat(result.getDurationMs()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should create timeout result")
        void shouldCreateTimeoutResult() {
            ExecutionResult result = ExecutionResult.timeout(
                "exec-timeout", "partial output", "partial error", 30000);

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.isTimedOut()).isTrue();
            assertThat(result.getExitCode()).isEqualTo(-1);
            assertThat(result.getStdout()).isEqualTo("partial output");
            assertThat(result.getDurationMs()).isEqualTo(30000);
            assertThat(result.getErrorMessage()).contains("timed out");
        }

        @Test
        @DisplayName("Should create resource limit exceeded result")
        void shouldCreateResourceLimitResult() {
            ExecutionResult result = ExecutionResult.resourceLimitExceeded(
                "exec-oom", "", "Out of memory", 2000, "memory");

            assertThat(result.isSuccess()).isFalse();
            assertThat(result.isResourceLimitExceeded()).isTrue();
            assertThat(result.getExitCode()).isEqualTo(-1);
            assertThat(result.getErrorMessage()).contains("memory");
            assertThat(result.getStderr()).isEqualTo("Out of memory");
        }
    }

    @Nested
    @DisplayName("Output Variables Conversion")
    class OutputVariablesTests {

        @Test
        @DisplayName("Should convert to output variables map")
        void shouldConvertToOutputVariables() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("hello")
                .stderr("")
                .durationMs(100)
                .success(true)
                .timedOut(false)
                .resourceLimitExceeded(false)
                .build();

            Map<String, Object> vars = result.toOutputVariables();

            assertThat(vars).containsEntry("executionId", "exec-123");
            assertThat(vars).containsEntry("exitCode", 0);
            assertThat(vars).containsEntry("stdout", "hello");
            assertThat(vars).containsEntry("stderr", "");
            assertThat(vars).containsEntry("durationMs", 100L);
            assertThat(vars).containsEntry("success", true);
            assertThat(vars).containsEntry("timedOut", false);
            assertThat(vars).containsEntry("resourceLimitExceeded", false);
            assertThat(vars).containsEntry("errorMessage", "");
        }

        @Test
        @DisplayName("Should handle null values in output variables")
        void shouldHandleNullValues() {
            ExecutionResult result = ExecutionResult.builder()
                .exitCode(1)
                .success(false)
                .build();

            Map<String, Object> vars = result.toOutputVariables();

            assertThat(vars).containsEntry("executionId", "");
            assertThat(vars).containsEntry("stdout", "");
            assertThat(vars).containsEntry("stderr", "");
            assertThat(vars).containsEntry("errorMessage", "");
        }

        @Test
        @DisplayName("Should include error message when present")
        void shouldIncludeErrorMessage() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-error")
                .exitCode(1)
                .success(false)
                .errorMessage("Something went wrong")
                .build();

            Map<String, Object> vars = result.toOutputVariables();

            assertThat(vars).containsEntry("errorMessage", "Something went wrong");
        }
    }

    @Nested
    @DisplayName("Resource Usage")
    class ResourceUsageTests {

        @Test
        @DisplayName("Should build resource usage")
        void shouldBuildResourceUsage() {
            ExecutionResult.ResourceUsage usage = ExecutionResult.ResourceUsage.builder()
                .peakMemoryBytes(104857600) // 100 MB
                .cpuTimeMs(5000)
                .bytesRead(10000)
                .bytesWritten(5000)
                .build();

            assertThat(usage.getPeakMemoryBytes()).isEqualTo(104857600);
            assertThat(usage.getCpuTimeMs()).isEqualTo(5000);
            assertThat(usage.getBytesRead()).isEqualTo(10000);
            assertThat(usage.getBytesWritten()).isEqualTo(5000);
        }

        @Test
        @DisplayName("Should include resource usage in result")
        void shouldIncludeResourceUsageInResult() {
            ExecutionResult.ResourceUsage usage = ExecutionResult.ResourceUsage.builder()
                .peakMemoryBytes(52428800) // 50 MB
                .cpuTimeMs(2500)
                .build();

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-with-usage")
                .exitCode(0)
                .success(true)
                .resourceUsage(usage)
                .build();

            assertThat(result.getResourceUsage()).isNotNull();
            assertThat(result.getResourceUsage().getPeakMemoryBytes()).isEqualTo(52428800);
            assertThat(result.getResourceUsage().getCpuTimeMs()).isEqualTo(2500);
        }

        @Test
        @DisplayName("Should handle zero resource usage")
        void shouldHandleZeroResourceUsage() {
            ExecutionResult.ResourceUsage usage = ExecutionResult.ResourceUsage.builder()
                .peakMemoryBytes(0)
                .cpuTimeMs(0)
                .bytesRead(0)
                .bytesWritten(0)
                .build();

            assertThat(usage.getPeakMemoryBytes()).isZero();
            assertThat(usage.getCpuTimeMs()).isZero();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle very large stdout")
        void shouldHandleLargeStdout() {
            StringBuilder largeOutput = new StringBuilder();
            for (int i = 0; i < 100000; i++) {
                largeOutput.append("Line ").append(i).append("\n");
            }

            ExecutionResult result = ExecutionResult.success(
                "exec-large", largeOutput.toString(), "", 10000);

            assertThat(result.getStdout().length()).isGreaterThan(1000000);
        }

        @Test
        @DisplayName("Should handle negative exit code")
        void shouldHandleNegativeExitCode() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-signal")
                .exitCode(-9) // Killed by SIGKILL
                .success(false)
                .build();

            assertThat(result.getExitCode()).isEqualTo(-9);
        }

        @Test
        @DisplayName("Should handle high exit code")
        void shouldHandleHighExitCode() {
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-high")
                .exitCode(255)
                .success(false)
                .build();

            assertThat(result.getExitCode()).isEqualTo(255);
        }

        @Test
        @DisplayName("Should handle unicode in output")
        void shouldHandleUnicodeOutput() {
            ExecutionResult result = ExecutionResult.success(
                "exec-unicode", "Hello 世界! 🌍", "", 100);

            assertThat(result.getStdout()).isEqualTo("Hello 世界! 🌍");
        }

        @Test
        @DisplayName("Should handle special characters in stderr")
        void shouldHandleSpecialCharsInStderr() {
            ExecutionResult result = ExecutionResult.failure(
                "exec-special", 1, "", "Error: \t\n\r\\\"'`$()[]{}",
                100, "Special chars in error");

            assertThat(result.getStderr()).contains("\t");
            assertThat(result.getStderr()).contains("\\");
        }
    }

    @Nested
    @DisplayName("Timing Tests")
    class TimingTests {

        @Test
        @DisplayName("Should calculate duration correctly")
        void shouldCalculateDuration() {
            Instant start = Instant.parse("2024-01-01T10:00:00Z");
            Instant end = Instant.parse("2024-01-01T10:00:05Z");

            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-timing")
                .exitCode(0)
                .success(true)
                .startTime(start)
                .endTime(end)
                .durationMs(5000)
                .build();

            assertThat(result.getDurationMs()).isEqualTo(5000);
            assertThat(result.getStartTime()).isEqualTo(start);
            assertThat(result.getEndTime()).isEqualTo(end);
        }

        @Test
        @DisplayName("Should handle zero duration")
        void shouldHandleZeroDuration() {
            ExecutionResult result = ExecutionResult.success("exec-instant", "", "", 0);

            assertThat(result.getDurationMs()).isZero();
        }

        @Test
        @DisplayName("Should handle very long duration")
        void shouldHandleLongDuration() {
            long oneHour = 3600000; // 1 hour in ms
            ExecutionResult result = ExecutionResult.builder()
                .executionId("exec-long")
                .exitCode(0)
                .success(true)
                .durationMs(oneHour)
                .build();

            assertThat(result.getDurationMs()).isEqualTo(oneHour);
        }
    }

    @Nested
    @DisplayName("Equality Tests")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal for same values")
        void shouldBeEqualForSameValues() {
            ExecutionResult result1 = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("hello")
                .success(true)
                .build();

            ExecutionResult result2 = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .stdout("hello")
                .success(true)
                .build();

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal for different exit codes")
        void shouldNotBeEqualForDifferentExitCodes() {
            ExecutionResult result1 = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(0)
                .success(true)
                .build();

            ExecutionResult result2 = ExecutionResult.builder()
                .executionId("exec-123")
                .exitCode(1)
                .success(false)
                .build();

            assertThat(result1).isNotEqualTo(result2);
        }
    }
}
