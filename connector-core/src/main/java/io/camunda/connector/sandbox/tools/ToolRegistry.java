package io.camunda.connector.sandbox.tools;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ToolDefinition;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of available CLI tools and their configurations.
 */
@Slf4j
@Component
public class ToolRegistry {

    private final SandboxConfig config;
    private final ObjectMapper yamlMapper;
    private final Map<String, ToolDefinition> tools = new ConcurrentHashMap<>();

    public ToolRegistry(SandboxConfig config) {
        this.config = config;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        this.yamlMapper.findAndRegisterModules();
    }

    @PostConstruct
    public void init() {
        loadToolRegistry();
    }

    /**
     * Load tool definitions from the registry file.
     */
    public void loadToolRegistry() {
        // First try external file path
        String registryPath = config.getToolRegistryPath();
        if (registryPath != null && !registryPath.isBlank()) {
            File registryFile = new File(registryPath);
            if (registryFile.exists()) {
                try {
                    loadFromFile(registryFile);
                    return;
                } catch (IOException e) {
                    log.warn("Failed to load tool registry from {}: {}", registryPath, e.getMessage());
                }
            }
        }

        // Fall back to classpath resource
        try {
            loadFromClasspath();
        } catch (IOException e) {
            log.error("Failed to load tool registry from classpath: {}", e.getMessage());
            loadBuiltInDefaults();
        }
    }

    /**
     * Load from external file.
     */
    private void loadFromFile(File registryFile) throws IOException {
        log.info("Loading tool registry from file: {}", registryFile.getAbsolutePath());
        ToolRegistryConfig registryConfig = yamlMapper.readValue(registryFile, ToolRegistryConfig.class);
        processRegistryConfig(registryConfig);
    }

    /**
     * Load from classpath resource.
     */
    private void loadFromClasspath() throws IOException {
        log.info("Loading tool registry from classpath");
        ClassPathResource resource = new ClassPathResource("tools/registry.yaml");
        try (InputStream is = resource.getInputStream()) {
            ToolRegistryConfig registryConfig = yamlMapper.readValue(is, ToolRegistryConfig.class);
            processRegistryConfig(registryConfig);
        }
    }

    /**
     * Process the registry configuration.
     */
    private void processRegistryConfig(ToolRegistryConfig registryConfig) {
        if (registryConfig.getTools() != null) {
            for (Map.Entry<String, ToolDefinition> entry : registryConfig.getTools().entrySet()) {
                ToolDefinition tool = entry.getValue();
                // Ensure name is set from the key if not present
                if (tool.getName() == null || tool.getName().isBlank()) {
                    tool.setName(entry.getKey());
                }
                tools.put(tool.getName().toLowerCase(), tool);
                log.debug("Loaded tool definition: {}", tool.getName());
            }
        }
        log.info("Loaded {} tool definitions", tools.size());
    }

    /**
     * Load built-in tool definitions.
     */
    private void loadBuiltInDefaults() {
        log.info("Loading built-in tool definitions");

        // curl
        tools.put("curl", ToolDefinition.builder()
                .name("curl")
                .displayName("curl")
                .description("Command line tool for transferring data with URLs")
                .version("latest")
                .category("utility")
                .installMethod("SYSTEM")
                .binaryPath("/bin/curl")
                .networkAccess(true)
                .seccompProfile("network")
                .build());

        // jq
        tools.put("jq", ToolDefinition.builder()
                .name("jq")
                .displayName("jq")
                .description("Command-line JSON processor")
                .version("latest")
                .category("utility")
                .installMethod("SYSTEM")
                .binaryPath("/bin/jq")
                .networkAccess(false)
                .seccompProfile("strict")
                .build());

        // grep
        tools.put("grep", ToolDefinition.builder()
                .name("grep")
                .displayName("grep")
                .description("Search for patterns in files")
                .version("latest")
                .category("utility")
                .installMethod("SYSTEM")
                .binaryPath("/bin/grep")
                .networkAccess(false)
                .seccompProfile("strict")
                .build());

        // sed
        tools.put("sed", ToolDefinition.builder()
                .name("sed")
                .displayName("sed")
                .description("Stream editor for filtering and transforming text")
                .version("latest")
                .category("utility")
                .installMethod("SYSTEM")
                .binaryPath("/bin/sed")
                .networkAccess(false)
                .seccompProfile("strict")
                .build());

        // awk
        tools.put("awk", ToolDefinition.builder()
                .name("awk")
                .displayName("awk")
                .description("Pattern scanning and processing language")
                .version("latest")
                .category("utility")
                .installMethod("SYSTEM")
                .binaryPath("/bin/awk")
                .networkAccess(false)
                .seccompProfile("strict")
                .build());

        log.info("Loaded {} built-in tool definitions", tools.size());
    }

    /**
     * Check if a tool definition exists.
     */
    public boolean hasToolDefinition(String toolName) {
        return tools.containsKey(toolName.toLowerCase());
    }

    /**
     * Get a tool definition by name.
     */
    public ToolDefinition getToolDefinition(String toolName) {
        return tools.get(toolName.toLowerCase());
    }

    /**
     * Get all registered tools.
     */
    public Map<String, ToolDefinition> getAllTools() {
        return Map.copyOf(tools);
    }

    /**
     * Register a new tool definition.
     */
    public void registerTool(ToolDefinition tool) {
        tools.put(tool.getName().toLowerCase(), tool);
        log.info("Registered tool: {}", tool.getName());
    }

    /**
     * Get tools by category.
     */
    public Map<String, ToolDefinition> getToolsByCategory(String category) {
        Map<String, ToolDefinition> result = new ConcurrentHashMap<>();
        for (Map.Entry<String, ToolDefinition> entry : tools.entrySet()) {
            if (category.equalsIgnoreCase(entry.getValue().getCategory())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    /**
     * Configuration model for the registry YAML file.
     * Supports map-based tool definitions.
     */
    @Data
    public static class ToolRegistryConfig {
        /**
         * Map of tool name to tool definition
         */
        private Map<String, ToolDefinition> tools;

        /**
         * Tool categories configuration
         */
        private Map<String, CategoryConfig> categories;

        /**
         * Global settings
         */
        private SettingsConfig settings;
    }

    /**
     * Category configuration.
     */
    @Data
    public static class CategoryConfig {
        private String description;
        private String defaultSeccompProfile;
        private boolean defaultNetworkAccess;
    }

    /**
     * Global settings configuration.
     */
    @Data
    public static class SettingsConfig {
        private ToolDefinition.ResourceLimits defaultResourceLimits;
        private String toolsBaseDir;
        private boolean cacheEnabled;
        private int cacheTtlHours;
        private boolean verifyChecksums;
        private boolean allowTenantVersionOverride;
    }
}
