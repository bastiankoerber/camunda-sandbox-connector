package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.TenantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Comprehensive tests for ArgumentSanitizer.
 * Tests argument validation and sanitization.
 */
@DisplayName("ArgumentSanitizer")
class ArgumentSanitizerTest {

    private ArgumentSanitizer argumentSanitizer;
    private TenantPolicy defaultPolicy;

    @BeforeEach
    void setUp() {
        argumentSanitizer = new ArgumentSanitizer();
        
        // Create a default policy for testing
        defaultPolicy = TenantPolicy.builder()
                .tenantId("test-tenant")
                .tenantName("Test Tenant")
                .enabled(true)
                .allowedTools(List.of(
                        TenantPolicy.ToolPolicy.builder()
                                .name("kubectl")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(false)
                                .build(),
                        TenantPolicy.ToolPolicy.builder()
                                .name("curl")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(true)
                                .blockedArguments(List.of("-o\\s*/", "--output\\s*/"))
                                .build()
                ))
                .build();
    }

    @Nested
    @DisplayName("Null and safe input")
    class NullAndSafeInput {

        @Test
        @DisplayName("should accept null argument")
        void shouldAcceptNullArgument() {
            assertThatCode(() -> argumentSanitizer.sanitize(null, "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "get",
                "pods",
                "--namespace",
                "-n",
                "default",
                "--output=json",
                "-o=yaml",
                "my-pod-name",
                "my_pod_name",
                "pod123",
                "--selector=app=nginx",
                "https://example.com",
                "file.txt",
                "data.json"
        })
        @DisplayName("should accept safe argument: {0}")
        void shouldAcceptSafeArgument(String argument) {
            assertThatCode(() -> argumentSanitizer.sanitize(argument, "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Argument length validation")
    class ArgumentLengthValidation {

        @Test
        @DisplayName("should reject argument exceeding max length")
        void shouldRejectLongArgument() {
            String longArgument = "a".repeat(4097);
            
            assertThatThrownBy(() -> argumentSanitizer.sanitize(longArgument, "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("too long");
        }

        @Test
        @DisplayName("should accept argument at max length")
        void shouldAcceptMaxLengthArgument() {
            String maxArgument = "a".repeat(4096);
            
            assertThatCode(() -> argumentSanitizer.sanitize(maxArgument, "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Null byte detection")
    class NullByteDetection {

        @Test
        @DisplayName("should reject argument with null byte")
        void shouldRejectNullByte() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("file\0name", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Null bytes");
        }
    }

    @Nested
    @DisplayName("Path traversal detection")
    class PathTraversalDetection {

        @Test
        @DisplayName("should reject parent directory traversal")
        void shouldRejectParentTraversal() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("../secret", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("traversal");
        }

        @Test
        @DisplayName("should reject multiple parent traversal")
        void shouldRejectMultipleParentTraversal() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("../../etc/passwd", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("traversal");
        }

        @Test
        @DisplayName("should reject absolute path starting with /")
        void shouldRejectAbsolutePath() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("/etc/passwd", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }

        @Test
        @DisplayName("should reject home directory path")
        void shouldRejectHomePath() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("~/secret", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }
    }

    @Nested
    @DisplayName("System path detection")
    class SystemPathDetection {

        @ParameterizedTest
        @ValueSource(strings = {
                "/etc/passwd",
                "/etc/shadow",
                "/proc/self/cmdline",
                "/sys/kernel/",
                "/dev/null",
                "/root/.ssh/",
                "/home/user/.bashrc",
                "/var/run/docker.sock",
                "/var/log/auth.log",
                "/boot/grub/grub.cfg",
                "/lib/x86_64-linux-gnu/",
                "/usr/lib/ssl/",
                "/bin/sh",
                "/sbin/init",
                "/usr/bin/sudo",
                "/usr/sbin/useradd"
        })
        @DisplayName("should reject system path: {0}")
        void shouldRejectSystemPath(String path) {
            assertThatThrownBy(() -> argumentSanitizer.sanitize(path, "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }
    }

    @Nested
    @DisplayName("Control character detection")
    class ControlCharacterDetection {

        @Test
        @DisplayName("should reject bell character")
        void shouldRejectBellCharacter() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("arg\u0007value", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should reject escape character")
        void shouldRejectEscapeCharacter() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("arg\u001Bvalue", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should reject form feed character")
        void shouldRejectFormFeedCharacter() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("arg\u000Cvalue", "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should allow tab character")
        void shouldAllowTabCharacter() {
            assertThatCode(() -> argumentSanitizer.sanitize("arg\tvalue", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should allow newline character")
        void shouldAllowNewlineCharacter() {
            assertThatCode(() -> argumentSanitizer.sanitize("line1\nline2", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should allow carriage return character")
        void shouldAllowCarriageReturnCharacter() {
            assertThatCode(() -> argumentSanitizer.sanitize("line1\rline2", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Tool-specific blocked arguments")
    class ToolSpecificBlockedArguments {

        @Test
        @DisplayName("should reject blocked argument pattern for curl")
        void shouldRejectBlockedArgumentForCurl() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("-o /tmp/malicious", "curl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }

        @Test
        @DisplayName("should reject --output to root for curl")
        void shouldRejectOutputToRootForCurl() {
            assertThatThrownBy(() -> argumentSanitizer.sanitize("--output /etc/passwd", "curl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }

        @Test
        @DisplayName("should allow non-blocked arguments for curl")
        void shouldAllowNonBlockedArgumentsForCurl() {
            assertThatCode(() -> argumentSanitizer.sanitize("-v", "curl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should not apply curl blocks to kubectl")
        void shouldNotApplyCurlBlocksToKubectl() {
            // kubectl doesn't have blocked arguments in the policy
            assertThatCode(() -> argumentSanitizer.sanitize("-o yaml", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("sanitizeAll method")
    class SanitizeAllMethod {

        @Test
        @DisplayName("should accept null argument list")
        void shouldAcceptNullArgumentList() {
            assertThatCode(() -> argumentSanitizer.sanitizeAll(null, "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept empty argument list")
        void shouldAcceptEmptyArgumentList() {
            assertThatCode(() -> argumentSanitizer.sanitizeAll(List.of(), "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should validate all arguments in list")
        void shouldValidateAllArguments() {
            List<String> args = List.of("get", "pods", "-n", "default");
            
            assertThatCode(() -> argumentSanitizer.sanitizeAll(args, "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should reject if any argument is invalid")
        void shouldRejectIfAnyArgumentInvalid() {
            List<String> args = List.of("get", "/etc/passwd", "-n", "default");
            
            assertThatThrownBy(() -> argumentSanitizer.sanitizeAll(args, "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }

        @Test
        @DisplayName("should reject if total length exceeds maximum")
        void shouldRejectIfTotalLengthExceedsMaximum() {
            // Create arguments that total more than 65536 bytes
            String longArg = "a".repeat(20000);
            List<String> args = List.of(longArg, longArg, longArg, longArg);
            
            assertThatThrownBy(() -> argumentSanitizer.sanitizeAll(args, "kubectl", defaultPolicy))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Total arguments length");
        }
    }

    @Nested
    @DisplayName("Real-world argument scenarios")
    class RealWorldArgumentScenarios {

        @Test
        @DisplayName("should accept kubectl selector argument")
        void shouldAcceptKubectlSelector() {
            assertThatCode(() -> argumentSanitizer.sanitize(
                    "--selector=app=nginx,env=production", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept kubectl label selector with special chars")
        void shouldAcceptKubectlLabelSelector() {
            assertThatCode(() -> argumentSanitizer.sanitize(
                    "--label-columns=kubernetes.io/name", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept JSON filter for jq")
        void shouldAcceptJqFilter() {
            assertThatCode(() -> argumentSanitizer.sanitize(
                    ".items[] | select(.status == \"Running\")", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept URL for curl")
        void shouldAcceptUrlForCurl() {
            assertThatCode(() -> argumentSanitizer.sanitize(
                    "https://api.example.com/v1/users?page=1&limit=10", "curl", defaultPolicy))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept S3 URI for aws")
        void shouldAcceptS3Uri() {
            assertThatCode(() -> argumentSanitizer.sanitize(
                    "s3://my-bucket/path/to/file.json", "kubectl", defaultPolicy))
                    .doesNotThrowAnyException();
        }
    }
}
