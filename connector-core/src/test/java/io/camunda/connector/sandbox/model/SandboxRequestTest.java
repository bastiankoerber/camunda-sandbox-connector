package io.camunda.connector.sandbox.model;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

/**
 * Test suite for SandboxRequest - request validation and building.
 */
class SandboxRequestTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("Request Building")
    class RequestBuildingTests {

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildWithAllFields() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -s https://api.example.com")
                .allowedTools(List.of("curl"))
                .toolVersions(Map.of("curl", "7.88"))
                .timeoutSeconds("60")
                .memoryLimitMb("512")
                .cpuLimitMillis(2000)
                .networkAccess(SandboxRequest.NetworkAccess.RESTRICTED)
                .workingDirectory("/workspace")
                .environment(Map.of("API_KEY", "secret"))
                .tenantId("tenant-123")
                .inputData("input data")
                .arguments(List.of("--extra-arg"))
                .build();

            assertThat(request.getCommand()).isEqualTo("curl -s https://api.example.com");
            assertThat(request.getAllowedTools()).containsExactly("curl");
            assertThat(request.getToolVersions()).containsEntry("curl", "7.88");
            assertThat(request.getTimeoutSeconds()).isEqualTo("60");
            assertThat(request.getMemoryLimitMb()).isEqualTo("512");
            assertThat(request.getCpuLimitMillis()).isEqualTo(2000);
            assertThat(request.getNetworkAccess()).isEqualTo(SandboxRequest.NetworkAccess.RESTRICTED);
            assertThat(request.getWorkingDirectory()).isEqualTo("/workspace");
            assertThat(request.getEnvironment()).containsEntry("API_KEY", "secret");
            assertThat(request.getTenantId()).isEqualTo("tenant-123");
            assertThat(request.getInputData()).isEqualTo("input data");
            assertThat(request.getArguments()).containsExactly("--extra-arg");
        }

        @Test
        @DisplayName("Should use default values")
        void shouldUseDefaults() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .build();

            assertThat(request.getTimeoutSeconds()).isEqualTo("30");
            assertThat(request.getMemoryLimitMb()).isEqualTo("256");
            assertThat(request.getCpuLimitMillis()).isEqualTo(1000);
            assertThat(request.getNetworkAccess()).isEqualTo(SandboxRequest.NetworkAccess.NONE);
        }

        @Test
        @DisplayName("Should allow minimal request")
        void shouldAllowMinimalRequest() {
            SandboxRequest request = SandboxRequest.builder()
                .command("ls")
                .allowedTools(List.of("ls"))
                .build();

            assertThat(request.getCommand()).isEqualTo("ls");
            assertThat(request.getAllowedTools()).containsExactly("ls");
        }
    }

    @Nested
    @DisplayName("Request Validation")
    class RequestValidationTests {

        @Test
        @DisplayName("Should validate valid request")
        void shouldValidateValidRequest() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .cpuLimitMillis(1000)
                .build();

            Set<ConstraintViolation<SandboxRequest>> violations = validator.validate(request);
            assertThat(violations).isEmpty();
        }

        // Tests for null/blank command removed - command can now be null 
        // when using selectedTool + commandArguments to construct command

        @Test
        @DisplayName("Should reject empty allowed tools")
        void shouldRejectEmptyAllowedTools() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of())
                .build();

            Set<ConstraintViolation<SandboxRequest>> violations = validator.validate(request);
            assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("allowedTools"));
        }

        @Test
        @DisplayName("Should reject null allowed tools")
        void shouldRejectNullAllowedTools() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(null)
                .build();

            Set<ConstraintViolation<SandboxRequest>> violations = validator.validate(request);
            assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("allowedTools"));
        }

        // Tests for timeout and memory validation removed - these are now String types
        // and validation is done at runtime via getTimeoutSecondsInt()/getMemoryLimitMbInt()

        @Test
        @DisplayName("Should reject CPU limit less than 100")
        void shouldRejectInvalidCpuLimit() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .cpuLimitMillis(50)
                .build();

            Set<ConstraintViolation<SandboxRequest>> violations = validator.validate(request);
            assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("cpuLimitMillis"));
        }
    }

    @Nested
    @DisplayName("Network Access Modes")
    class NetworkAccessTests {

        @Test
        @DisplayName("Should have all network access modes")
        void shouldHaveAllModes() {
            SandboxRequest.NetworkAccess[] modes = SandboxRequest.NetworkAccess.values();

            assertThat(modes).containsExactlyInAnyOrder(
                SandboxRequest.NetworkAccess.NONE,
                SandboxRequest.NetworkAccess.INTERNAL,
                SandboxRequest.NetworkAccess.RESTRICTED,
                SandboxRequest.NetworkAccess.FULL
            );
        }

        @Test
        @DisplayName("Should allow setting each network mode")
        void shouldAllowEachMode() {
            for (SandboxRequest.NetworkAccess mode : SandboxRequest.NetworkAccess.values()) {
                SandboxRequest request = SandboxRequest.builder()
                    .command("test")
                    .allowedTools(List.of("test"))
                    .networkAccess(mode)
                    .build();

                assertThat(request.getNetworkAccess()).isEqualTo(mode);
            }
        }
    }

    @Nested
    @DisplayName("Environment Variables")
    class EnvironmentVariableTests {

        @Test
        @DisplayName("Should handle multiple environment variables")
        void shouldHandleMultipleEnvVars() {
            Map<String, String> env = Map.of(
                "VAR1", "value1",
                "VAR2", "value2",
                "VAR3", "value3"
            );

            SandboxRequest request = SandboxRequest.builder()
                .command("env")
                .allowedTools(List.of("env"))
                .environment(env)
                .build();

            assertThat(request.getEnvironment()).hasSize(3);
            assertThat(request.getEnvironment()).containsEntry("VAR1", "value1");
        }

        @Test
        @DisplayName("Should handle empty environment")
        void shouldHandleEmptyEnvironment() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .environment(Map.of())
                .build();

            assertThat(request.getEnvironment()).isEmpty();
        }

        @Test
        @DisplayName("Should handle null environment")
        void shouldHandleNullEnvironment() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .environment(null)
                .build();

            assertThat(request.getEnvironment()).isNull();
        }
    }

    @Nested
    @DisplayName("Tool Versions")
    class ToolVersionTests {

        @Test
        @DisplayName("Should handle tool version constraints")
        void shouldHandleToolVersions() {
            Map<String, String> versions = Map.of(
                "python3", "3.11",
                "node", "18.x",
                "curl", "latest"
            );

            SandboxRequest request = SandboxRequest.builder()
                .command("python3 --version")
                .allowedTools(List.of("python3", "node", "curl"))
                .toolVersions(versions)
                .build();

            assertThat(request.getToolVersions()).hasSize(3);
            assertThat(request.getToolVersions()).containsEntry("python3", "3.11");
        }

        @Test
        @DisplayName("Should handle null tool versions")
        void shouldHandleNullToolVersions() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .toolVersions(null)
                .build();

            assertThat(request.getToolVersions()).isNull();
        }
    }

    @Nested
    @DisplayName("Arguments")
    class ArgumentTests {

        @Test
        @DisplayName("Should handle additional arguments")
        void shouldHandleArguments() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl")
                .allowedTools(List.of("curl"))
                .arguments(List.of("-s", "-X", "POST", "https://api.example.com"))
                .build();

            assertThat(request.getArguments()).hasSize(4);
            assertThat(request.getArguments()).containsExactly("-s", "-X", "POST", "https://api.example.com");
        }

        @Test
        @DisplayName("Should handle empty arguments")
        void shouldHandleEmptyArguments() {
            SandboxRequest request = SandboxRequest.builder()
                .command("ls")
                .allowedTools(List.of("ls"))
                .arguments(List.of())
                .build();

            assertThat(request.getArguments()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Input Data")
    class InputDataTests {

        @Test
        @DisplayName("Should handle input data")
        void shouldHandleInputData() {
            String inputJson = "{\"key\": \"value\"}";

            SandboxRequest request = SandboxRequest.builder()
                .command("jq .")
                .allowedTools(List.of("jq"))
                .inputData(inputJson)
                .build();

            assertThat(request.getInputData()).isEqualTo(inputJson);
        }

        @Test
        @DisplayName("Should handle large input data")
        void shouldHandleLargeInputData() {
            StringBuilder largeInput = new StringBuilder();
            for (int i = 0; i < 10000; i++) {
                largeInput.append("line ").append(i).append("\n");
            }

            SandboxRequest request = SandboxRequest.builder()
                .command("wc -l")
                .allowedTools(List.of("wc"))
                .inputData(largeInput.toString())
                .build();

            assertThat(request.getInputData()).isNotEmpty();
            assertThat(request.getInputData().length()).isGreaterThan(50000);
        }
    }

    @Nested
    @DisplayName("Equality and HashCode")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal for same values")
        void shouldBeEqualForSameValues() {
            SandboxRequest request1 = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .tenantId("tenant-1")
                .build();

            SandboxRequest request2 = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .tenantId("tenant-1")
                .build();

            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal for different commands")
        void shouldNotBeEqualForDifferentCommands() {
            SandboxRequest request1 = SandboxRequest.builder()
                .command("echo hello")
                .allowedTools(List.of("echo"))
                .build();

            SandboxRequest request2 = SandboxRequest.builder()
                .command("echo world")
                .allowedTools(List.of("echo"))
                .build();

            assertThat(request1).isNotEqualTo(request2);
        }
    }

    @Nested
    @DisplayName("Script Content")
    class ScriptContentTests {

        @Test
        @DisplayName("Should detect script content mode")
        void shouldDetectScriptContentMode() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("import json\nprint(json.dumps({'key': 'value'}))")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.hasScriptContent()).isTrue();
            assertThat(request.getScriptContent()).contains("import json");
        }

        @Test
        @DisplayName("Should not detect script content mode when empty")
        void shouldNotDetectScriptContentModeWhenEmpty() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .allowedTools(List.of("jq"))
                .build();

            assertThat(request.hasScriptContent()).isFalse();
        }

        @Test
        @DisplayName("Should not detect script content mode when blank")
        void shouldNotDetectScriptContentModeWhenBlank() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("   ")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.hasScriptContent()).isFalse();
        }

        @Test
        @DisplayName("Should default script language to python")
        void shouldDefaultScriptLanguageToPython() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("print('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getEffectiveScriptLanguage()).isEqualTo("python");
        }

        @Test
        @DisplayName("Should use provided script language")
        void shouldUseProvidedScriptLanguage() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("print('hello')")
                .scriptLanguage("Python")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getEffectiveScriptLanguage()).isEqualTo("python");
        }

        @Test
        @DisplayName("Should return null effective command when script content present")
        void shouldReturnNullEffectiveCommandWhenScriptContentPresent() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("print('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getEffectiveCommand()).isNull();
        }

        @Test
        @DisplayName("Should return effective command when no script content")
        void shouldReturnEffectiveCommandWhenNoScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .allowedTools(List.of("jq"))
                .build();

            assertThat(request.getEffectiveCommand()).isEqualTo("jq '.'");
        }
    }

    @Nested
    @DisplayName("Script Content Validation")
    class ScriptContentValidationTests {

        @Test
        @DisplayName("Should throw error when both command and scriptContent provided")
        void shouldThrowErrorWhenBothCommandAndScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .scriptContent("print('hello')")
                .allowedTools(List.of("jq", "safe-python3"))
                .build();

            assertThatThrownBy(request::validateMutualExclusivity)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cannot specify both");
        }

        @Test
        @DisplayName("Should throw error when both selectedTool+commandArguments and scriptContent provided")
        void shouldThrowErrorWhenBothToolArgsAndScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .selectedTool("jq")
                .commandArguments("'.'")
                .scriptContent("print('hello')")
                .allowedTools(List.of("jq", "safe-python3"))
                .build();

            assertThatThrownBy(request::validateMutualExclusivity)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cannot specify both");
        }

        @Test
        @DisplayName("Should pass validation with only command")
        void shouldPassValidationWithOnlyCommand() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .allowedTools(List.of("jq"))
                .build();

            assertThatCode(request::validateMutualExclusivity).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should pass validation with only scriptContent")
        void shouldPassValidationWithOnlyScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("print('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThatCode(request::validateMutualExclusivity).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should throw error when neither command nor scriptContent for execute action")
        void shouldThrowErrorWhenNeitherCommandNorScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .action("execute")
                .allowedTools(List.of("jq"))
                .build();

            assertThatThrownBy(request::validateMutualExclusivity)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be provided");
        }

        @Test
        @DisplayName("Should pass validation for getCapabilities action without command")
        void shouldPassValidationForGetCapabilities() {
            SandboxRequest request = SandboxRequest.builder()
                .action("getCapabilities")
                .allowedTools(List.of("jq"))
                .build();

            assertThatCode(request::validateMutualExclusivity).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should pass validation for getToolHelp action without command")
        void shouldPassValidationForGetToolHelp() {
            SandboxRequest request = SandboxRequest.builder()
                .action("getToolHelp")
                .allowedTools(List.of("jq"))
                .build();

            assertThatCode(request::validateMutualExclusivity).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should throw error for unsupported script language")
        void shouldThrowErrorForUnsupportedScriptLanguage() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("console.log('hello')")
                .scriptLanguage("javascript")
                .allowedTools(List.of("node"))
                .build();

            assertThatThrownBy(request::validateScriptLanguage)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported script language")
                .hasMessageContaining("javascript");
        }

        @Test
        @DisplayName("Should pass validation for python script language")
        void shouldPassValidationForPythonScriptLanguage() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("print('hello')")
                .scriptLanguage("python")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThatCode(request::validateScriptLanguage).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should pass validation when no script content (language validation skipped)")
        void shouldPassValidationWhenNoScriptContent() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .scriptLanguage("javascript") // ignored because no scriptContent
                .allowedTools(List.of("jq"))
                .build();

            assertThatCode(request::validateScriptLanguage).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Script Content Sanitization Tests")
    class ScriptContentSanitizationTests {

        @Test
        @DisplayName("Should strip leading double quote from script content")
        void shouldStripLeadingDoubleQuote() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("\"import json\nprint('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("import json\nprint('hello')");
        }

        @Test
        @DisplayName("Should strip wrapping double quotes from script content")
        void shouldStripWrappingDoubleQuotes() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("\"import json\nprint('hello')\"")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("import json\nprint('hello')");
        }

        @Test
        @DisplayName("Should strip wrapping single quotes from script content")
        void shouldStripWrappingSingleQuotes() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("'import json\nprint(\"hello\")'")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("import json\nprint(\"hello\")");
        }

        @Test
        @DisplayName("Should unescape newlines in script content")
        void shouldUnescapeNewlines() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("import json\\nprint('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("import json\nprint('hello')");
        }

        @Test
        @DisplayName("Should unescape tabs in script content")
        void shouldUnescapeTabs() {
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("if True:\\n\\tprint('hello')")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("if True:\n\tprint('hello')");
        }

        @Test
        @DisplayName("Should handle FEEL-style escaped content")
        void shouldHandleFeelStyleEscapedContent() {
            // This simulates what FEEL might return: "import json\nprint(\"hello\")"
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent("\"import json\\nprint(\\\"hello\\\")\"")
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo("import json\nprint(\"hello\")");
        }

        @Test
        @DisplayName("Should leave clean script content unchanged")
        void shouldLeaveCleanScriptContentUnchanged() {
            String script = "import json\nprint(json.dumps({'key': 'value'}))";
            SandboxRequest request = SandboxRequest.builder()
                .scriptContent(script)
                .allowedTools(List.of("safe-python3"))
                .build();

            assertThat(request.getScriptContent()).isEqualTo(script);
        }

        @Test
        @DisplayName("Should return null when script content is null")
        void shouldReturnNullWhenScriptContentIsNull() {
            SandboxRequest request = SandboxRequest.builder()
                .command("jq '.'")
                .allowedTools(List.of("jq"))
                .build();

            assertThat(request.getScriptContent()).isNull();
        }
    }
}
