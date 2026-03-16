package io.camunda.connector.sandbox.sandbox;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for NsjailConfigBuilder - ensures correct nsjail command line generation.
 * 
 * CRITICAL: These tests prevent regressions in nsjail flag handling.
 * 
 * Key issues these tests catch:
 * 1. Boolean flags (--disable_clone_newpid, --keep_env) should NOT have value arguments
 * 2. The command after -- must be the actual executable, not "false" or other garbage
 * 3. Namespace disable flags should only be added when namespaces are DISABLED
 * 4. Environment variables should use --env KEY=VALUE format
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NsjailConfigBuilderTest {

    @Mock
    private SandboxConfig config;

    @Mock
    private SandboxConfig.SecurityConfig securityConfig;

    @TempDir
    Path tempDir;

    private NsjailConfigBuilder builder;

    @BeforeEach
    void setUp() {
        when(config.getSecurity()).thenReturn(securityConfig);
        when(config.getNsjailPath()).thenReturn("/usr/bin/nsjail");
        when(config.getSandboxRootfs()).thenReturn("/sandbox/rootfs");
        when(config.getToolsDirectory()).thenReturn("/sandbox/tools");
        
        // Default security settings - all namespaces enabled
        when(securityConfig.isUseUserNamespace()).thenReturn(true);
        when(securityConfig.isUsePidNamespace()).thenReturn(true);
        when(securityConfig.isUseMountNamespace()).thenReturn(true);
        when(securityConfig.getSandboxUid()).thenReturn(65534);
        when(securityConfig.getSandboxGid()).thenReturn(65534);

        builder = new NsjailConfigBuilder(config);
    }

    @Nested
    @DisplayName("Boolean Flag Handling Tests")
    class BooleanFlagTests {

        /**
         * CRITICAL TEST: Ensures "false" or "true" never appears as a standalone argument
         * after boolean flags.
         * 
         * If this test fails, nsjail will interpret "false" or "true" as the command
         * to execute, causing errors like: process:'false'
         */
        @Test
        @DisplayName("Should NEVER have 'false' or 'true' as standalone arguments after boolean flags")
        void shouldNeverHaveFalseOrTrueAsStandaloneArguments() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            // Find the index of -- (command separator)
            int separatorIndex = cmd.indexOf("--");
            assertThat(separatorIndex).isGreaterThan(0);

            // Check all arguments BEFORE the -- separator
            List<String> nsjailArgs = cmd.subList(1, separatorIndex); // Skip nsjail path

            for (int i = 0; i < nsjailArgs.size(); i++) {
                String arg = nsjailArgs.get(i);
                String prevArg = i > 0 ? nsjailArgs.get(i - 1) : "";
                
                // "false" or "true" should never appear as standalone values after boolean flags
                if (arg.equals("false") || arg.equals("true")) {
                    // Check if previous arg is a boolean flag
                    if (prevArg.startsWith("--disable_") || 
                        prevArg.equals("--keep_env") ||
                        prevArg.equals("--keep_caps") ||
                        prevArg.equals("--silent") ||
                        prevArg.equals("--skip_setsid")) {
                        fail("Found '" + arg + "' after boolean flag '" + prevArg + 
                             "'. Boolean flags don't take arguments! nsjail will interpret '" + 
                             arg + "' as the command to execute.");
                    }
                }
            }
        }

        @Test
        @DisplayName("Should NOT add --disable_clone_newpid when PID namespace is ENABLED")
        void shouldNotAddDisablePidFlagWhenEnabled() {
            when(securityConfig.isUsePidNamespace()).thenReturn(true);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).doesNotContain("--disable_clone_newpid");
        }

        @Test
        @DisplayName("Should add --disable_clone_newpid when PID namespace is DISABLED")
        void shouldAddDisablePidFlagWhenDisabled() {
            when(securityConfig.isUsePidNamespace()).thenReturn(false);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).contains("--disable_clone_newpid");
            
            // Verify no argument after the flag
            int flagIndex = cmd.indexOf("--disable_clone_newpid");
            String nextArg = cmd.get(flagIndex + 1);
            assertThat(nextArg)
                .withFailMessage("--disable_clone_newpid should not have an argument, but found: " + nextArg)
                .doesNotMatch("true|false");
        }

        @Test
        @DisplayName("Should NOT add --disable_clone_newns when mount namespace is ENABLED")
        void shouldNotAddDisableMountFlagWhenEnabled() {
            when(securityConfig.isUseMountNamespace()).thenReturn(true);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).doesNotContain("--disable_clone_newns");
        }

        @Test
        @DisplayName("Should add --disable_clone_newns when mount namespace is DISABLED")
        void shouldAddDisableMountFlagWhenDisabled() {
            when(securityConfig.isUseMountNamespace()).thenReturn(false);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).contains("--disable_clone_newns");
            
            // Verify no argument after the flag
            int flagIndex = cmd.indexOf("--disable_clone_newns");
            String nextArg = cmd.get(flagIndex + 1);
            assertThat(nextArg)
                .withFailMessage("--disable_clone_newns should not have an argument, but found: " + nextArg)
                .doesNotMatch("true|false");
        }

        @Test
        @DisplayName("Should add --disable_clone_newnet when network access is requested")
        void shouldAddDisableNetFlagWhenNetworkRequested() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .networkAccess(SandboxRequest.NetworkAccess.FULL)
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).contains("--disable_clone_newnet");
            
            // Verify no argument after the flag
            int flagIndex = cmd.indexOf("--disable_clone_newnet");
            String nextArg = cmd.get(flagIndex + 1);
            assertThat(nextArg)
                .withFailMessage("--disable_clone_newnet should not have an argument, but found: " + nextArg)
                .doesNotMatch("true|false");
        }

        @Test
        @DisplayName("Should NOT add --disable_clone_newnet when no network access")
        void shouldNotAddDisableNetFlagWhenNoNetwork() {
            SandboxRequest request = createDefaultRequest(); // NONE network access
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).doesNotContain("--disable_clone_newnet");
        }
    }

    @Nested
    @DisplayName("Command Structure Tests")
    class CommandStructureTests {

        /**
         * CRITICAL TEST: The command after -- must be the actual executable.
         * If boolean flags have arguments, the "argument" becomes the command.
         */
        @Test
        @DisplayName("Command after -- separator should be the actual executable")
        void commandAfterSeparatorShouldBeExecutable() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = ParsedCommand.builder()
                .executable("curl")
                .arguments(List.of("-s", "https://example.com"))
                .build();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int separatorIndex = cmd.indexOf("--");
            assertThat(separatorIndex).isGreaterThan(0);

            // The argument immediately after -- should be "curl", not "false" or anything else
            String actualCommand = cmd.get(separatorIndex + 1);
            assertThat(actualCommand)
                .withFailMessage("Expected 'curl' after --, but got: " + actualCommand)
                .isEqualTo("curl");
        }

        @Test
        @DisplayName("Full command should follow -- separator")
        void fullCommandShouldFollowSeparator() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = ParsedCommand.builder()
                .executable("jq")
                .arguments(List.of("-r", ".name"))
                .build();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int separatorIndex = cmd.indexOf("--");
            List<String> commandPart = cmd.subList(separatorIndex + 1, cmd.size());

            assertThat(commandPart).containsExactly("jq", "-r", ".name");
        }

        @Test
        @DisplayName("Should handle command with no arguments")
        void shouldHandleCommandWithNoArguments() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = ParsedCommand.builder()
                .executable("whoami")
                .arguments(List.of())
                .build();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int separatorIndex = cmd.indexOf("--");
            List<String> commandPart = cmd.subList(separatorIndex + 1, cmd.size());

            assertThat(commandPart).containsExactly("whoami");
        }
    }

    @Nested
    @DisplayName("Environment Variable Tests")
    class EnvironmentVariableTests {

        @Test
        @DisplayName("Should pass environment variables with --env KEY=VALUE format")
        void shouldPassEnvVariablesCorrectly() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://api.example.com")
                .allowedTools(List.of("curl"))
                .environment(Map.of("API_KEY", "secret123", "DEBUG", "true"))
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            // Find all --env arguments
            int envCount = 0;
            for (int i = 0; i < cmd.size() - 1; i++) {
                if (cmd.get(i).equals("--env")) {
                    envCount++;
                    String envValue = cmd.get(i + 1);
                    assertThat(envValue).matches("\\w+=.+");
                }
            }

            assertThat(envCount).isEqualTo(2);
            
            // Verify specific values
            assertThat(cmd).contains("--env", "API_KEY=secret123");
            assertThat(cmd).contains("--env", "DEBUG=true");
        }

        @Test
        @DisplayName("Should handle null environment")
        void shouldHandleNullEnvironment() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .environment(null)
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            // Should not throw
            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).doesNotContain("--env");
        }

        @Test
        @DisplayName("Should handle empty environment map")
        void shouldHandleEmptyEnvironment() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .environment(Map.of())
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            // Should have -- but no --env before it
            int separatorIndex = cmd.indexOf("--");
            List<String> beforeSeparator = cmd.subList(0, separatorIndex);
            assertThat(beforeSeparator).doesNotContain("--env");
        }
    }

    @Nested
    @DisplayName("Resource Limit Tests")
    class ResourceLimitTests {

        @Test
        @DisplayName("Should set time limit from request")
        void shouldSetTimeLimit() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("60")
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int timeLimitIndex = cmd.indexOf("--time_limit");
            assertThat(timeLimitIndex).isGreaterThan(0);
            assertThat(cmd.get(timeLimitIndex + 1)).isEqualTo("60");
        }

        @Test
        @DisplayName("Should set memory limit from request")
        void shouldSetMemoryLimit() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .memoryLimitMb("512")
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int memLimitIndex = cmd.indexOf("--rlimit_as");
            assertThat(memLimitIndex).isGreaterThan(0);
            assertThat(cmd.get(memLimitIndex + 1)).isEqualTo("512");
        }

        @Test
        @DisplayName("Should set CPU limit 5 seconds more than timeout")
        void shouldSetCpuLimitCorrectly() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl https://example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("30")
                .build();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int cpuLimitIndex = cmd.indexOf("--rlimit_cpu");
            assertThat(cpuLimitIndex).isGreaterThan(0);
            assertThat(cmd.get(cpuLimitIndex + 1)).isEqualTo("35"); // 30 + 5
        }
    }

    @Nested
    @DisplayName("Path Configuration Tests")
    class PathConfigurationTests {

        @Test
        @DisplayName("Should use configured nsjail path")
        void shouldUseConfiguredNsjailPath() {
            when(config.getNsjailPath()).thenReturn("/custom/path/nsjail");
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd.get(0)).isEqualTo("/custom/path/nsjail");
        }

        @Test
        @DisplayName("Should use configured rootfs path")
        void shouldUseConfiguredRootfsPath() {
            when(config.getSandboxRootfs()).thenReturn("/custom/rootfs");
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int chrootIndex = cmd.indexOf("--chroot");
            assertThat(cmd.get(chrootIndex + 1)).isEqualTo("/custom/rootfs");
        }

        @Test
        @DisplayName("Should mount workspace with correct path")
        void shouldMountWorkspaceCorrectly() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace-123");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int bindmountIndex = cmd.indexOf("--bindmount");
            String mountArg = cmd.get(bindmountIndex + 1);
            assertThat(mountArg).endsWith(":/workspace");
            assertThat(mountArg).startsWith(workspacePath.toString());
        }

        @Test
        @DisplayName("Should set working directory to /workspace")
        void shouldSetWorkingDirectory() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            int cwdIndex = cmd.indexOf("--cwd");
            assertThat(cmd.get(cwdIndex + 1)).isEqualTo("/workspace");
        }
    }

    @Nested
    @DisplayName("User/Group Mapping Tests")
    class UserGroupMappingTests {

        @Test
        @DisplayName("Should add user/group mapping when user namespace is enabled")
        void shouldAddUserMappingWhenEnabled() {
            when(securityConfig.isUseUserNamespace()).thenReturn(true);
            when(securityConfig.getSandboxUid()).thenReturn(1000);
            when(securityConfig.getSandboxGid()).thenReturn(1000);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).contains("--user", "1000");
            assertThat(cmd).contains("--group", "1000");
        }

        @Test
        @DisplayName("Should NOT add user/group mapping when user namespace is disabled")
        void shouldNotAddUserMappingWhenDisabled() {
            when(securityConfig.isUseUserNamespace()).thenReturn(false);
            
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            assertThat(cmd).doesNotContain("--user");
            assertThat(cmd).doesNotContain("--group");
        }
    }

    @Nested
    @DisplayName("Complete Command Validation Tests")
    class CompleteCommandValidationTests {

        @Test
        @DisplayName("Generated command should be valid for nsjail execution")
        void generatedCommandShouldBeValid() {
            SandboxRequest request = SandboxRequest.builder()
                .command("curl -s https://api.example.com")
                .allowedTools(List.of("curl"))
                .timeoutSeconds("30")
                .memoryLimitMb("256")
                .networkAccess(SandboxRequest.NetworkAccess.FULL)
                .environment(Map.of("API_KEY", "test"))
                .build();
            
            ParsedCommand parsedCommand = ParsedCommand.builder()
                .executable("curl")
                .arguments(List.of("-s", "https://api.example.com"))
                .build();
            
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            // Basic structure validation
            assertThat(cmd.get(0)).isEqualTo("/usr/bin/nsjail");
            assertThat(cmd).contains("--mode", "o");
            assertThat(cmd).contains("--time_limit", "30");
            assertThat(cmd).contains("--rlimit_as", "256");
            assertThat(cmd).contains("--chroot", "/sandbox/rootfs");
            assertThat(cmd).contains("--cwd", "/workspace");
            assertThat(cmd).contains("--");
            
            // Network access requested, so network namespace should be disabled
            assertThat(cmd).contains("--disable_clone_newnet");
            
            // Environment should be passed
            assertThat(cmd).contains("--env", "API_KEY=test");
            
            // Command should be at the end
            int separatorIndex = cmd.indexOf("--");
            List<String> actualCommand = cmd.subList(separatorIndex + 1, cmd.size());
            assertThat(actualCommand).containsExactly("curl", "-s", "https://api.example.com");
        }

        @Test
        @DisplayName("Command should never contain --keep_env flag")
        void commandShouldNotContainKeepEnvFlag() {
            SandboxRequest request = createDefaultRequest();
            ParsedCommand parsedCommand = createCurlCommand();
            Path workspacePath = tempDir.resolve("workspace");

            List<String> cmd = builder.buildCommand(request, parsedCommand, workspacePath);

            // --keep_env should NOT be in the command as we pass env vars explicitly
            assertThat(cmd).doesNotContain("--keep_env");
        }
    }

    // Helper methods

    private SandboxRequest createDefaultRequest() {
        return SandboxRequest.builder()
            .command("curl https://example.com")
            .allowedTools(List.of("curl"))
            .timeoutSeconds("30")
            .memoryLimitMb("256")
            .networkAccess(SandboxRequest.NetworkAccess.NONE)
            .build();
    }

    private ParsedCommand createCurlCommand() {
        return ParsedCommand.builder()
            .executable("curl")
            .arguments(List.of("https://example.com"))
            .build();
    }
}
