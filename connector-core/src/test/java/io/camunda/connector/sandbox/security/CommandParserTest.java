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
 * Comprehensive tests for CommandParser.
 * Tests command tokenization, quoting, and validation.
 */
@DisplayName("CommandParser")
class CommandParserTest {

    private CommandParser commandParser;

    @BeforeEach
    void setUp() {
        commandParser = new CommandParser();
    }

    @Nested
    @DisplayName("Basic parsing")
    class BasicParsing {

        @Test
        @DisplayName("should parse simple command")
        void shouldParseSimpleCommand() {
            ParsedCommand result = commandParser.parse("kubectl");

            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).isEmpty();
            assertThat(result.getRawCommand()).isEqualTo("kubectl");
            assertThat(result.isContainsShellFeatures()).isFalse();
        }

        @Test
        @DisplayName("should parse command with single argument")
        void shouldParseCommandWithSingleArgument() {
            ParsedCommand result = commandParser.parse("kubectl version");

            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly("version");
        }

        @Test
        @DisplayName("should parse command with multiple arguments")
        void shouldParseCommandWithMultipleArguments() {
            ParsedCommand result = commandParser.parse("kubectl get pods -n default");

            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly("get", "pods", "-n", "default");
        }

        @Test
        @DisplayName("should trim whitespace")
        void shouldTrimWhitespace() {
            ParsedCommand result = commandParser.parse("  kubectl  get  pods  ");

            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly("get", "pods");
        }
    }

    @Nested
    @DisplayName("Quoted string handling")
    class QuotedStringHandling {

        @Test
        @DisplayName("should parse double-quoted argument")
        void shouldParseDoubleQuotedArgument() {
            ParsedCommand result = commandParser.parse("echo \"hello world\"");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("hello world");
        }

        @Test
        @DisplayName("should parse single-quoted argument")
        void shouldParseSingleQuotedArgument() {
            ParsedCommand result = commandParser.parse("echo 'hello world'");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("hello world");
        }

        @Test
        @DisplayName("should handle escape sequences in double quotes")
        void shouldHandleEscapeSequencesInDoubleQuotes() {
            ParsedCommand result = commandParser.parse("echo \"line1\\nline2\"");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("line1\nline2");
        }

        @Test
        @DisplayName("should handle escaped quote in double quotes")
        void shouldHandleEscapedQuoteInDoubleQuotes() {
            ParsedCommand result = commandParser.parse("echo \"say \\\"hello\\\"\"");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("say \"hello\"");
        }

        @Test
        @DisplayName("should handle escaped backslash in double quotes")
        void shouldHandleEscapedBackslash() {
            ParsedCommand result = commandParser.parse("echo \"path\\\\to\\\\file\"");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("path\\to\\file");
        }

        @Test
        @DisplayName("should not process escapes in single quotes")
        void shouldNotProcessEscapesInSingleQuotes() {
            ParsedCommand result = commandParser.parse("echo 'no\\nescape'");

            assertThat(result.getExecutable()).isEqualTo("echo");
            assertThat(result.getArguments()).containsExactly("no\\nescape");
        }

        @Test
        @DisplayName("should handle mixed quoted and unquoted arguments")
        void shouldHandleMixedQuotedAndUnquotedArguments() {
            ParsedCommand result = commandParser.parse("cmd arg1 \"arg 2\" 'arg 3' arg4");

            assertThat(result.getExecutable()).isEqualTo("cmd");
            assertThat(result.getArguments()).containsExactly("arg1", "arg 2", "arg 3", "arg4");
        }

        @Test
        @DisplayName("should handle JSON argument in quotes")
        void shouldHandleJsonArgument() {
            ParsedCommand result = commandParser.parse("jq '{\"name\": \"value\"}'");

            assertThat(result.getExecutable()).isEqualTo("jq");
            assertThat(result.getArguments()).containsExactly("{\"name\": \"value\"}");
        }
    }

    @Nested
    @DisplayName("Empty and null input")
    class EmptyAndNullInput {

        @Test
        @DisplayName("should reject null command")
        void shouldRejectNullCommand() {
            assertThatThrownBy(() -> commandParser.parse(null))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        @DisplayName("should reject empty command")
        void shouldRejectEmptyCommand() {
            assertThatThrownBy(() -> commandParser.parse(""))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        @DisplayName("should reject whitespace-only command")
        void shouldRejectWhitespaceOnlyCommand() {
            assertThatThrownBy(() -> commandParser.parse("   "))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("empty");
        }
    }

    @Nested
    @DisplayName("Shell operator detection")
    class ShellOperatorDetection {

        @Test
        @DisplayName("should reject semicolon operator")
        void shouldRejectSemicolon() {
            assertThatThrownBy(() -> commandParser.parse("ls; rm -rf /"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject pipe operator")
        void shouldRejectPipe() {
            assertThatThrownBy(() -> commandParser.parse("cat file | grep text"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject AND operator")
        void shouldRejectAndOperator() {
            assertThatThrownBy(() -> commandParser.parse("true && echo yes"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject output redirect")
        void shouldRejectOutputRedirect() {
            assertThatThrownBy(() -> commandParser.parse("echo test > file.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject input redirect")
        void shouldRejectInputRedirect() {
            assertThatThrownBy(() -> commandParser.parse("cmd < input.txt"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject command substitution $(...)")
        void shouldRejectDollarParenSubstitution() {
            assertThatThrownBy(() -> commandParser.parse("echo $(whoami)"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }

        @Test
        @DisplayName("should reject backtick substitution")
        void shouldRejectBacktickSubstitution() {
            assertThatThrownBy(() -> commandParser.parse("echo `whoami`"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Shell operators");
        }
    }

    @Nested
    @DisplayName("Executable name validation")
    class ExecutableNameValidation {

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

        @Test
        @DisplayName("should reject absolute path")
        void shouldRejectAbsolutePath() {
            assertThatThrownBy(() -> commandParser.parse("/bin/ls"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("paths are not allowed");
        }

        @Test
        @DisplayName("should reject relative path")
        void shouldRejectRelativePath() {
            assertThatThrownBy(() -> commandParser.parse("./malicious"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("paths are not allowed");
        }

        @Test
        @DisplayName("should reject path with backslash")
        void shouldRejectPathWithBackslash() {
            assertThatThrownBy(() -> commandParser.parse("dir\\cmd.exe"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("paths are not allowed");
        }

        @Test
        @DisplayName("should reject executable with special characters")
        void shouldRejectSpecialCharacters() {
            assertThatThrownBy(() -> commandParser.parse("cmd$test"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("invalid characters");
        }

        @Test
        @DisplayName("should reject very long executable name")
        void shouldRejectLongExecutableName() {
            String longName = "a".repeat(65);
            assertThatThrownBy(() -> commandParser.parse(longName))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("too long");
        }

        @ParameterizedTest
        @ValueSource(strings = {"kubectl", "aws", "gcloud", "terraform", "helm", "jq", "yq", "curl"})
        @DisplayName("should accept valid tool names: {0}")
        void shouldAcceptValidToolNames(String toolName) {
            assertThatCode(() -> commandParser.parse(toolName + " --version"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept executable with dash")
        void shouldAcceptDash() {
            assertThatCode(() -> commandParser.parse("my-tool"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept executable with underscore")
        void shouldAcceptUnderscore() {
            assertThatCode(() -> commandParser.parse("my_tool"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept executable with dot")
        void shouldAcceptDot() {
            assertThatCode(() -> commandParser.parse("tool.exe"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("should accept executable with numbers")
        void shouldAcceptNumbers() {
            assertThatCode(() -> commandParser.parse("kubectl2"))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("toCommandList and toSafeString")
    class OutputMethods {

        @Test
        @DisplayName("toCommandList should include executable and arguments")
        void toCommandListShouldIncludeAll() {
            ParsedCommand result = commandParser.parse("kubectl get pods -n default");

            assertThat(result.toCommandList())
                    .containsExactly("kubectl", "get", "pods", "-n", "default");
        }

        @Test
        @DisplayName("toSafeString should quote arguments with spaces")
        void toSafeStringShouldQuoteSpaces() {
            ParsedCommand result = commandParser.parse("echo \"hello world\"");

            String safeString = result.toSafeString();
            assertThat(safeString).contains("'hello world'");
        }

        @Test
        @DisplayName("toSafeString should escape single quotes")
        void toSafeStringShouldEscapeSingleQuotes() {
            ParsedCommand result = commandParser.parse("echo \"it's\"");

            String safeString = result.toSafeString();
            assertThat(safeString).contains("'\\''");
        }
    }

    @Nested
    @DisplayName("Real-world command scenarios")
    class RealWorldScenarios {

        @Test
        @DisplayName("should parse kubectl get pods command")
        void shouldParseKubectlGetPods() {
            ParsedCommand result = commandParser.parse(
                    "kubectl get pods -n kube-system --selector=app=nginx"
            );

            assertThat(result.getExecutable()).isEqualTo("kubectl");
            assertThat(result.getArguments()).containsExactly(
                    "get", "pods", "-n", "kube-system", "--selector=app=nginx"
            );
        }

        @Test
        @DisplayName("should parse AWS S3 command")
        void shouldParseAwsS3Command() {
            ParsedCommand result = commandParser.parse(
                    "aws s3 ls s3://my-bucket/path/"
            );

            assertThat(result.getExecutable()).isEqualTo("aws");
            assertThat(result.getArguments()).containsExactly("s3", "ls", "s3://my-bucket/path/");
        }

        @Test
        @DisplayName("should parse jq with filter")
        void shouldParseJqWithFilter() {
            ParsedCommand result = commandParser.parse(
                    "jq '.items[] | .metadata.name'"
            );

            assertThat(result.getExecutable()).isEqualTo("jq");
            assertThat(result.getArguments()).containsExactly(".items[] | .metadata.name");
        }

        @Test
        @DisplayName("should parse terraform command")
        void shouldParseTerraformCommand() {
            ParsedCommand result = commandParser.parse(
                    "terraform plan -var-file=\"production.tfvars\" -out=plan.out"
            );

            assertThat(result.getExecutable()).isEqualTo("terraform");
            assertThat(result.getArguments()).containsExactly(
                    "plan", "-var-file=production.tfvars", "-out=plan.out"
            );
        }

        @Test
        @DisplayName("should parse helm with complex values")
        void shouldParseHelmWithComplexValues() {
            ParsedCommand result = commandParser.parse(
                    "helm upgrade --set 'image.tag=v1.0.0' myrelease mychart"
            );

            assertThat(result.getExecutable()).isEqualTo("helm");
            assertThat(result.getArguments()).containsExactly(
                    "upgrade", "--set", "image.tag=v1.0.0", "myrelease", "mychart"
            );
        }
    }
}
