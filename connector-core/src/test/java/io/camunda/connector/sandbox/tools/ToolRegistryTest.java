package io.camunda.connector.sandbox.tools;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ToolDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive tests for ToolRegistry.
 * Tests tool definition management without relying on YAML loading.
 */
@DisplayName("ToolRegistry")
class ToolRegistryTest {

    private ToolRegistry toolRegistry;

    @BeforeEach
    void setUp() {
        // Create a minimal config for testing
        SandboxConfig config = new SandboxConfig();
        config.setToolRegistryPath(null); // Will use built-in defaults
        
        SandboxConfig.ExecutionConfig execConfig = new SandboxConfig.ExecutionConfig();
        execConfig.setMaxTimeoutSeconds(300);
        execConfig.setMaxMemoryMb(512);
        config.setExecution(execConfig);
        
        toolRegistry = new ToolRegistry(config);
        // Don't call init/loadToolRegistry to avoid classpath issues in tests
    }

    @Nested
    @DisplayName("Built-in defaults loading")
    class BuiltInDefaultsLoading {

        @Test
        @DisplayName("should have empty tools before loading")
        void shouldHaveEmptyToolsBeforeLoading() {
            assertThat(toolRegistry.getAllTools()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Tool registration")
    class ToolRegistration {

        @Test
        @DisplayName("should register new tool")
        void shouldRegisterNewTool() {
            ToolDefinition newTool = ToolDefinition.builder()
                    .name("newtool")
                    .displayName("New Tool")
                    .description("A new testing tool")
                    .version("1.0.0")
                    .category("testing")
                    .build();
            
            toolRegistry.registerTool(newTool);
            
            assertThat(toolRegistry.hasToolDefinition("newtool")).isTrue();
            assertThat(toolRegistry.getToolDefinition("newtool")).isEqualTo(newTool);
        }

        @Test
        @DisplayName("should overwrite existing tool on re-registration")
        void shouldOverwriteExistingTool() {
            ToolDefinition tool1 = ToolDefinition.builder()
                    .name("testtool")
                    .displayName("Test Tool v1")
                    .version("1.0.0")
                    .build();
            
            ToolDefinition tool2 = ToolDefinition.builder()
                    .name("testtool")
                    .displayName("Test Tool v2")
                    .version("2.0.0")
                    .build();
            
            toolRegistry.registerTool(tool1);
            toolRegistry.registerTool(tool2);
            
            ToolDefinition result = toolRegistry.getToolDefinition("testtool");
            assertThat(result.getVersion()).isEqualTo("2.0.0");
            assertThat(result.getDisplayName()).isEqualTo("Test Tool v2");
        }
    }

    @Nested
    @DisplayName("Tool lookup")
    class ToolLookup {

        @BeforeEach
        void registerTools() {
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("kubectl")
                    .displayName("kubectl")
                    .description("Kubernetes command-line tool")
                    .build());
        }

        @Test
        @DisplayName("should find tool by name (case-insensitive)")
        void shouldFindToolByNameCaseInsensitive() {
            assertThat(toolRegistry.hasToolDefinition("kubectl")).isTrue();
            assertThat(toolRegistry.hasToolDefinition("KUBECTL")).isTrue();
            assertThat(toolRegistry.hasToolDefinition("KubeCtl")).isTrue();
        }

        @Test
        @DisplayName("should return null for non-existent tool")
        void shouldReturnNullForNonExistentTool() {
            assertThat(toolRegistry.getToolDefinition("nonexistent-tool-xyz")).isNull();
        }

        @Test
        @DisplayName("should correctly report tool existence")
        void shouldReportToolExistence() {
            assertThat(toolRegistry.hasToolDefinition("kubectl")).isTrue();
            assertThat(toolRegistry.hasToolDefinition("othertool")).isFalse();
        }
    }

    @Nested
    @DisplayName("Category filtering")
    class CategoryFiltering {

        @BeforeEach
        void registerTools() {
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("tool1")
                    .displayName("Tool 1")
                    .category("utility")
                    .build());
            
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("tool2")
                    .displayName("Tool 2")
                    .category("utility")
                    .build());
            
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("tool3")
                    .displayName("Tool 3")
                    .category("cloud")
                    .build());
        }

        @Test
        @DisplayName("should filter tools by category")
        void shouldFilterToolsByCategory() {
            Map<String, ToolDefinition> utilityTools = toolRegistry.getToolsByCategory("utility");
            
            assertThat(utilityTools).containsKey("tool1");
            assertThat(utilityTools).containsKey("tool2");
            assertThat(utilityTools).doesNotContainKey("tool3");
        }

        @Test
        @DisplayName("should filter tools by category case-insensitively")
        void shouldFilterToolsByCategoryIgnoreCase() {
            Map<String, ToolDefinition> cloudTools = toolRegistry.getToolsByCategory("CLOUD");
            
            assertThat(cloudTools).containsKey("tool3");
        }

        @Test
        @DisplayName("should return empty map for non-existent category")
        void shouldReturnEmptyMapForNonExistentCategory() {
            Map<String, ToolDefinition> result = toolRegistry.getToolsByCategory("nonexistent");
            
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Tool definition properties")
    class ToolDefinitionProperties {

        @Test
        @DisplayName("should preserve all tool properties")
        void shouldPreserveAllToolProperties() {
            ToolDefinition tool = ToolDefinition.builder()
                    .name("fulltool")
                    .displayName("Full Tool")
                    .description("A fully configured tool")
                    .version("1.0.0")
                    .category("testing")
                    .installMethod("DOWNLOAD")
                    .binaryPath("/usr/local/bin/fulltool")
                    .networkAccess(true)
                    .seccompProfile("network")
                    .build();
            
            toolRegistry.registerTool(tool);
            
            ToolDefinition retrieved = toolRegistry.getToolDefinition("fulltool");
            
            assertThat(retrieved.getName()).isEqualTo("fulltool");
            assertThat(retrieved.getDisplayName()).isEqualTo("Full Tool");
            assertThat(retrieved.getDescription()).isEqualTo("A fully configured tool");
            assertThat(retrieved.getVersion()).isEqualTo("1.0.0");
            assertThat(retrieved.getCategory()).isEqualTo("testing");
            assertThat(retrieved.getInstallMethod()).isEqualTo("DOWNLOAD");
            assertThat(retrieved.getBinaryPath()).isEqualTo("/usr/local/bin/fulltool");
            assertThat(retrieved.isNetworkAccess()).isTrue();
            assertThat(retrieved.getSeccompProfile()).isEqualTo("network");
        }
    }

    @Nested
    @DisplayName("Built-in tool binary paths")
    class BuiltInToolBinaryPathsTest {

        /**
         * CRITICAL TEST: Ensures built-in tools have correct binary paths.
         * 
         * The sandbox rootfs (Ubuntu-based) has binaries in /bin/, not /usr/bin/.
         * If paths are wrong, nsjail will fail with "No such file or directory".
         * 
         * Error pattern: execve('/usr/bin/curl') failed: No such file or directory
         */
        @Test
        @DisplayName("Built-in tools should have /bin/ paths, not /usr/bin/")
        void builtInToolsShouldHaveBinPaths() {
            // Load built-in defaults
            SandboxConfig config = new SandboxConfig();
            config.setToolRegistryPath(null);
            SandboxConfig.ExecutionConfig execConfig = new SandboxConfig.ExecutionConfig();
            execConfig.setMaxTimeoutSeconds(300);
            execConfig.setMaxMemoryMb(512);
            config.setExecution(execConfig);
            
            ToolRegistry registry = new ToolRegistry(config);
            // Call internal method to load built-in defaults
            registry.loadToolRegistry();
            
            // These tools MUST have /bin/ paths in the built-in defaults
            String[] criticalTools = {"curl", "jq", "grep", "sed", "awk"};
            
            for (String toolName : criticalTools) {
                if (registry.hasToolDefinition(toolName)) {
                    ToolDefinition tool = registry.getToolDefinition(toolName);
                    String binaryPath = tool.getBinaryPath();
                    
                    assertThat(binaryPath)
                        .withFailMessage("Tool '%s' has path '%s' but should start with /bin/. " +
                            "The sandbox rootfs uses /bin/, not /usr/bin/.", toolName, binaryPath)
                        .startsWith("/bin/");
                    
                    assertThat(binaryPath)
                        .withFailMessage("Tool '%s' has path '%s' which starts with /usr/bin/. " +
                            "This will fail in the sandbox. Change to /bin/%s", toolName, binaryPath, toolName)
                        .doesNotStartWith("/usr/bin/");
                }
            }
        }

        @Test
        @DisplayName("curl binary path should be /bin/curl")
        void curlBinaryPathShouldBeCorrect() {
            SandboxConfig config = new SandboxConfig();
            config.setToolRegistryPath(null);
            SandboxConfig.ExecutionConfig execConfig = new SandboxConfig.ExecutionConfig();
            execConfig.setMaxTimeoutSeconds(300);
            execConfig.setMaxMemoryMb(512);
            config.setExecution(execConfig);
            
            ToolRegistry registry = new ToolRegistry(config);
            registry.loadToolRegistry();
            
            if (registry.hasToolDefinition("curl")) {
                ToolDefinition curl = registry.getToolDefinition("curl");
                assertThat(curl.getBinaryPath())
                    .withFailMessage("curl binary path must be /bin/curl for sandbox execution")
                    .isEqualTo("/bin/curl");
            }
        }

        @Test
        @DisplayName("jq binary path should be /bin/jq")
        void jqBinaryPathShouldBeCorrect() {
            SandboxConfig config = new SandboxConfig();
            config.setToolRegistryPath(null);
            SandboxConfig.ExecutionConfig execConfig = new SandboxConfig.ExecutionConfig();
            execConfig.setMaxTimeoutSeconds(300);
            execConfig.setMaxMemoryMb(512);
            config.setExecution(execConfig);
            
            ToolRegistry registry = new ToolRegistry(config);
            registry.loadToolRegistry();
            
            if (registry.hasToolDefinition("jq")) {
                ToolDefinition jq = registry.getToolDefinition("jq");
                assertThat(jq.getBinaryPath())
                    .withFailMessage("jq binary path must be /bin/jq for sandbox execution")
                    .isEqualTo("/bin/jq");
            }
        }
    }

    @Nested
    @DisplayName("getAllTools method")
    class GetAllToolsMethod {

        @BeforeEach
        void registerTools() {
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("tool1")
                    .displayName("Tool 1")
                    .build());
        }

        @Test
        @DisplayName("should return immutable copy of tools map")
        void shouldReturnImmutableCopy() {
            Map<String, ToolDefinition> tools = toolRegistry.getAllTools();
            
            // Attempting to modify should throw exception
            org.junit.jupiter.api.Assertions.assertThrows(
                    UnsupportedOperationException.class,
                    () -> tools.put("newtool", ToolDefinition.builder().name("test").build())
            );
        }

        @Test
        @DisplayName("should not expose internal state")
        void shouldNotExposeInternalState() {
            Map<String, ToolDefinition> tools1 = toolRegistry.getAllTools();
            
            // Register a new tool
            toolRegistry.registerTool(ToolDefinition.builder()
                    .name("addedlater")
                    .displayName("Added Later")
                    .build());
            
            // Original copy should not contain the new tool
            assertThat(tools1).doesNotContainKey("addedlater");
            
            // Fresh copy should contain it
            assertThat(toolRegistry.getAllTools()).containsKey("addedlater");
        }
    }

    /**
     * CRITICAL TESTS: Ensure safe-python3 is properly configured in the tool registry.
     * These tests prevent the "Tool 'safe-python3' is not available in the tool registry" error.
     */
    @Nested
    @DisplayName("safe-python3 tool configuration")
    class SafePython3ToolConfiguration {

        private ToolRegistry loadedRegistry;

        @BeforeEach
        void loadRegistry() {
            SandboxConfig config = new SandboxConfig();
            config.setToolRegistryPath(null);
            SandboxConfig.ExecutionConfig execConfig = new SandboxConfig.ExecutionConfig();
            execConfig.setMaxTimeoutSeconds(300);
            execConfig.setMaxMemoryMb(512);
            config.setExecution(execConfig);
            
            loadedRegistry = new ToolRegistry(config);
            loadedRegistry.loadToolRegistry();
        }

        @Test
        @DisplayName("safe-python3 must be registered in tool registry")
        void safePython3MustBeRegistered() {
            assertThat(loadedRegistry.hasToolDefinition("safe-python3"))
                .withFailMessage("CRITICAL: safe-python3 must be in tool registry for script mode to work. " +
                    "Add it to tools/registry.yaml")
                .isTrue();
        }

        @Test
        @DisplayName("safe-python3 binary path must be /bin/safe-python3")
        void safePython3BinaryPathMustBeCorrect() {
            if (loadedRegistry.hasToolDefinition("safe-python3")) {
                ToolDefinition safePython3 = loadedRegistry.getToolDefinition("safe-python3");
                assertThat(safePython3.getBinaryPath())
                    .withFailMessage("safe-python3 binary path must be /bin/safe-python3")
                    .isEqualTo("/bin/safe-python3");
            }
        }

        @Test
        @DisplayName("safe-python3 must be in scripting category")
        void safePython3MustBeInScriptingCategory() {
            if (loadedRegistry.hasToolDefinition("safe-python3")) {
                ToolDefinition safePython3 = loadedRegistry.getToolDefinition("safe-python3");
                assertThat(safePython3.getCategory())
                    .withFailMessage("safe-python3 should be in 'scripting' category")
                    .isEqualTo("scripting");
            }
        }

        @Test
        @DisplayName("safe-python3 must not require network access")
        void safePython3MustNotRequireNetwork() {
            if (loadedRegistry.hasToolDefinition("safe-python3")) {
                ToolDefinition safePython3 = loadedRegistry.getToolDefinition("safe-python3");
                assertThat(safePython3.isNetworkAccess())
                    .withFailMessage("safe-python3 should not require network access for security")
                    .isFalse();
            }
        }

        @Test
        @DisplayName("safe-python3 must not require authentication")
        void safePython3MustNotRequireAuth() {
            if (loadedRegistry.hasToolDefinition("safe-python3")) {
                ToolDefinition safePython3 = loadedRegistry.getToolDefinition("safe-python3");
                assertThat(safePython3.isRequiresAuth())
                    .withFailMessage("safe-python3 should not require authentication")
                    .isFalse();
            }
        }

        @Test
        @DisplayName("python3 tool must also exist (alias check)")
        void python3ToolMustAlsoExist() {
            // Both python3 and safe-python3 should exist - python3 is the original,
            // safe-python3 is the alias used by element template
            assertThat(loadedRegistry.hasToolDefinition("python3"))
                .withFailMessage("python3 should also exist in registry alongside safe-python3")
                .isTrue();
        }
    }
}
