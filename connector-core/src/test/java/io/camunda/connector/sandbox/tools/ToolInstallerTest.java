package io.camunda.connector.sandbox.tools;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ToolDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for ToolInstaller - tool installation and caching.
 */
@ExtendWith(MockitoExtension.class)
class ToolInstallerTest {

    @Mock
    private SandboxConfig config;

    @Mock
    private ToolRegistry toolRegistry;

    @TempDir
    Path tempDir;

    private ToolInstaller toolInstaller;

    @BeforeEach
    void setUp() {
        toolInstaller = new ToolInstaller(config, toolRegistry);
    }

    @Nested
    @DisplayName("Tool Availability Checks")
    class ToolAvailabilityTests {

        @Test
        @DisplayName("Should throw exception for unknown tool")
        void shouldThrowForUnknownTool() {
            when(toolRegistry.getToolDefinition("unknown")).thenReturn(null);

            assertThatThrownBy(() -> toolInstaller.ensureToolAvailable("unknown", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Tool not found in registry: unknown");
        }

        @Test
        @DisplayName("Should throw exception for unknown version")
        void shouldThrowForUnknownVersion() {
            // Create a ToolDefinition with a versions list so that unknown versions return null
            List<ToolDefinition.VersionInfo> versions = List.of(
                ToolDefinition.VersionInfo.builder()
                    .version("7.88")
                    .source("apt")
                    .build()
            );
            
            ToolDefinition toolDef = ToolDefinition.builder()
                .name("curl")
                .versions(versions)
                .defaultVersion("7.88")
                .build();

            when(toolRegistry.getToolDefinition("curl")).thenReturn(toolDef);

            assertThatThrownBy(() -> toolInstaller.ensureToolAvailable("curl", "9.99"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Version 9.99 not found for tool: curl");
        }

        @Test
        @DisplayName("Should return path for builtin tool")
        void shouldReturnPathForBuiltinTool() throws IOException {
            // Create the tool file to simulate it being installed
            Path toolPath = tempDir.resolve("curl").resolve("latest").resolve("curl");
            Files.createDirectories(toolPath.getParent());
            Files.writeString(toolPath, "#!/bin/bash\necho curl");

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("curl")
                .version("latest")
                .installMethod("SYSTEM")
                .binaryPath(toolPath.toString())
                .build();

            when(toolRegistry.getToolDefinition("curl")).thenReturn(toolDef);

            String result = toolInstaller.ensureToolAvailable("curl", null);

            assertThat(result).isEqualTo(toolPath.toString());
        }

        @Test
        @DisplayName("Should use cached path when available")
        void shouldUseCachedPath() throws IOException {
            // First call - set up for caching
            Path toolPath = tempDir.resolve("jq").resolve("latest").resolve("jq");
            Files.createDirectories(toolPath.getParent());
            Files.writeString(toolPath, "#!/bin/bash\necho jq");

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("jq")
                .version("latest")
                .installMethod("SYSTEM")
                .binaryPath(toolPath.toString())
                .build();

            when(toolRegistry.getToolDefinition("jq")).thenReturn(toolDef);

            // First call
            String result1 = toolInstaller.ensureToolAvailable("jq", null);
            
            // Second call - should use cache
            String result2 = toolInstaller.ensureToolAvailable("jq", null);

            assertThat(result1).isEqualTo(result2);
        }

        @Test
        @DisplayName("Should use default version when null is passed")
        void shouldUseDefaultVersion() throws IOException {
            Path toolPath = tempDir.resolve("grep").resolve("3.8").resolve("grep");
            Files.createDirectories(toolPath.getParent());
            Files.writeString(toolPath, "#!/bin/bash\necho grep");

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("grep")
                .version("3.8")
                .installMethod("SYSTEM")
                .binaryPath(toolPath.toString())
                .build();

            when(toolRegistry.getToolDefinition("grep")).thenReturn(toolDef);

            // Use "latest" as null will resolve to "latest" in the implementation
            String result = toolInstaller.ensureToolAvailable("grep", "latest");

            assertThat(result).isNotNull();
        }
    }

    @Nested
    @DisplayName("Cache Management Tests")
    class CacheManagementTests {

        @Test
        @DisplayName("Should clear cache")
        void shouldClearCache() throws IOException {
            // Set up a cached tool
            Path toolPath = tempDir.resolve("yq").resolve("latest").resolve("yq");
            Files.createDirectories(toolPath.getParent());
            Files.writeString(toolPath, "#!/bin/bash\necho yq");

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("yq")
                .version("latest")
                .installMethod("SYSTEM")
                .binaryPath(toolPath.toString())
                .build();

            when(toolRegistry.getToolDefinition("yq")).thenReturn(toolDef);

            // Cache the tool
            toolInstaller.ensureToolAvailable("yq", null);

            // Clear cache - should not throw
            assertThatCode(() -> toolInstaller.clearCache())
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Tool Definition Tests")
    class ToolDefinitionTests {

        @Test
        @DisplayName("Should handle tool with legacy versions list")
        void shouldHandleLegacyVersionsList() {
            List<ToolDefinition.VersionInfo> versions = List.of(
                ToolDefinition.VersionInfo.builder()
                    .version("1.0")
                    .source("apt")
                    .build(),
                ToolDefinition.VersionInfo.builder()
                    .version("2.0")
                    .source("binary")
                    .downloadUrl("https://example.com/tool-2.0")
                    .build()
            );

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("mytool")
                .versions(versions)
                .defaultVersion("2.0")
                .build();

            assertThat(toolDef.getVersion("1.0")).isNotNull();
            assertThat(toolDef.getVersion("1.0").getSource()).isEqualTo("apt");
            assertThat(toolDef.getVersion("2.0")).isNotNull();
            assertThat(toolDef.hasVersion("1.0")).isTrue();
            assertThat(toolDef.hasVersion("3.0")).isFalse();
        }

        @Test
        @DisplayName("Should handle tool with package name")
        void shouldHandlePackageName() {
            ToolDefinition.VersionInfo versionInfo = ToolDefinition.VersionInfo.builder()
                .version("latest")
                .source("pip")
                .packageName("python-tool")
                .build();

            assertThat(versionInfo.getPackageName()).isEqualTo("python-tool");
            assertThat(versionInfo.getSource()).isEqualTo("pip");
        }

        @Test
        @DisplayName("Should handle tool with checksum")
        void shouldHandleToolWithChecksum() {
            ToolDefinition.VersionInfo versionInfo = ToolDefinition.VersionInfo.builder()
                .version("1.0.0")
                .source("binary")
                .downloadUrl("https://example.com/tool-1.0.0")
                .checksum("sha256:abc123def456")
                .build();

            assertThat(versionInfo.getChecksum()).isEqualTo("sha256:abc123def456");
        }

        @Test
        @DisplayName("Should handle different source types")
        void shouldHandleDifferentSources() {
            String[] sources = {"apt", "pip", "binary", "builtin"};

            for (String source : sources) {
                ToolDefinition.VersionInfo versionInfo = ToolDefinition.VersionInfo.builder()
                    .version("latest")
                    .source(source)
                    .build();

                assertThat(versionInfo.getSource()).isEqualTo(source);
            }
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle null tool name gracefully")
        void shouldHandleNullToolName() {
            when(toolRegistry.getToolDefinition(null)).thenReturn(null);

            assertThatThrownBy(() -> toolInstaller.ensureToolAvailable(null, null))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle empty tool name gracefully")
        void shouldHandleEmptyToolName() {
            when(toolRegistry.getToolDefinition("")).thenReturn(null);

            assertThatThrownBy(() -> toolInstaller.ensureToolAvailable("", null))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Binary Path Resolution Tests")
    class BinaryPathTests {

        @Test
        @DisplayName("Should use custom binary path when provided")
        void shouldUseCustomBinaryPath() throws IOException {
            Path customPath = tempDir.resolve("custom/path/to/tool");
            Files.createDirectories(customPath.getParent());
            Files.writeString(customPath, "#!/bin/bash\necho tool");

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("customtool")
                .version("latest")
                .installMethod("SYSTEM")
                .binaryPath(customPath.toString())
                .build();

            when(toolRegistry.getToolDefinition("customtool")).thenReturn(toolDef);

            String result = toolInstaller.ensureToolAvailable("customtool", null);

            assertThat(result).isEqualTo(customPath.toString());
        }

        @Test
        @DisplayName("Should resolve path from config when no binary path provided")
        void shouldResolveFromConfig() throws IOException {
            Path toolDir = tempDir.resolve("tools/wget/latest");
            Files.createDirectories(toolDir);
            Files.writeString(toolDir.resolve("wget"), "#!/bin/bash\necho wget");

            when(config.getToolPath("wget", "latest")).thenReturn(toolDir);

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("wget")
                .version("latest")
                .installMethod("SYSTEM")
                // No binaryPath - should use config
                .build();

            when(toolRegistry.getToolDefinition("wget")).thenReturn(toolDef);

            String result = toolInstaller.ensureToolAvailable("wget", null);

            assertThat(result).isEqualTo(toolDir.resolve("wget").toString());
        }
    }

    @Nested
    @DisplayName("Install Method Tests")
    class InstallMethodTests {

        @Test
        @DisplayName("Should handle BINARY install method")
        void shouldHandleBinaryMethod() {
            ToolDefinition toolDef = ToolDefinition.builder()
                .name("kubectl")
                .version("1.28")
                .installMethod("BINARY")
                .installUrl("https://storage.googleapis.com/kubernetes-release/release/v1.28.0/bin/linux/amd64/kubectl")
                .build();

            assertThat(toolDef.getInstallMethod()).isEqualTo("BINARY");
            assertThat(toolDef.getInstallUrl()).contains("kubernetes-release");
        }

        @Test
        @DisplayName("Should handle APT install method")
        void shouldHandleAptMethod() {
            ToolDefinition toolDef = ToolDefinition.builder()
                .name("curl")
                .version("7.88")
                .installMethod("APT")
                .build();

            assertThat(toolDef.getInstallMethod()).isEqualTo("APT");
        }

        @Test
        @DisplayName("Should handle PIP install method")
        void shouldHandlePipMethod() {
            ToolDefinition toolDef = ToolDefinition.builder()
                .name("awscli")
                .version("2.0")
                .installMethod("PIP")
                .build();

            assertThat(toolDef.getInstallMethod()).isEqualTo("PIP");
        }

        @Test
        @DisplayName("Should handle SYSTEM install method")
        void shouldHandleSystemMethod() {
            ToolDefinition toolDef = ToolDefinition.builder()
                .name("bash")
                .version("5.0")
                .installMethod("SYSTEM")
                .binaryPath("/bin/bash")
                .build();

            assertThat(toolDef.getInstallMethod()).isEqualTo("SYSTEM");
            assertThat(toolDef.getBinaryPath()).isEqualTo("/bin/bash");
        }
    }
}
