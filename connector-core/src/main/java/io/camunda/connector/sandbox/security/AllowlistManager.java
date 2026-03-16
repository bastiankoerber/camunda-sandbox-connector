package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.TenantPolicy;
import io.camunda.connector.sandbox.tools.ToolRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Manages tool allowlists and validates tool access.
 */
@Slf4j
@Component
public class AllowlistManager {

    private final ToolRegistry toolRegistry;

    public AllowlistManager(ToolRegistry toolRegistry) {
        this.toolRegistry = toolRegistry;
    }

    /**
     * Validate that a tool is allowed for execution.
     *
     * @param toolName The name of the tool to validate
     * @param requestedTools List of tools requested in the execution
     * @param tenantPolicy The tenant's security policy
     * @throws SecurityException if the tool is not allowed
     */
    public void validateTool(String toolName, List<String> requestedTools, TenantPolicy tenantPolicy) 
            throws SecurityException {
        
        log.debug("Validating tool: {} against allowlist", toolName);

        // 1. Check if tool is in the requested tools list
        if (requestedTools == null || !containsIgnoreCase(requestedTools, toolName)) {
            throw new SecurityException(
                    "Tool '" + toolName + "' is not in the list of allowed tools for this request");
        }

        // 2. Check if tool is allowed by tenant policy
        if (!tenantPolicy.isToolAllowed(toolName)) {
            throw new SecurityException(
                    "Tool '" + toolName + "' is not allowed for tenant: " + tenantPolicy.getTenantId());
        }

        // 3. Check if tool exists in the registry
        if (!toolRegistry.hasToolDefinition(toolName)) {
            throw new SecurityException(
                    "Tool '" + toolName + "' is not available in the tool registry");
        }

        log.debug("Tool '{}' passed allowlist validation", toolName);
    }

    /**
     * Validate that a specific tool version is allowed.
     *
     * @param toolName The name of the tool
     * @param version The requested version
     * @param tenantPolicy The tenant's security policy
     * @throws SecurityException if the version is not allowed
     */
    public void validateToolVersion(String toolName, String version, TenantPolicy tenantPolicy) 
            throws SecurityException {
        
        log.debug("Validating tool version: {}@{}", toolName, version);

        // Check tenant policy allows this version
        if (!tenantPolicy.isToolVersionAllowed(toolName, version)) {
            throw new SecurityException(
                    "Version '" + version + "' of tool '" + toolName + 
                    "' is not allowed for tenant: " + tenantPolicy.getTenantId());
        }

        // Check version exists in registry
        var toolDef = toolRegistry.getToolDefinition(toolName);
        if (toolDef != null && !toolDef.hasVersion(version)) {
            throw new SecurityException(
                    "Version '" + version + "' of tool '" + toolName + "' is not available");
        }

        log.debug("Tool version {}@{} passed validation", toolName, version);
    }

    /**
     * Check if all requested tools are available and allowed.
     *
     * @param requestedTools List of tools requested
     * @param tenantPolicy The tenant's security policy
     * @throws SecurityException if any tool is not allowed
     */
    public void validateAllTools(List<String> requestedTools, TenantPolicy tenantPolicy) 
            throws SecurityException {
        
        if (requestedTools == null || requestedTools.isEmpty()) {
            throw new SecurityException("At least one tool must be specified");
        }

        for (String tool : requestedTools) {
            if (!tenantPolicy.isToolAllowed(tool)) {
                throw new SecurityException(
                        "Tool '" + tool + "' is not allowed for tenant: " + tenantPolicy.getTenantId());
            }
            if (!toolRegistry.hasToolDefinition(tool)) {
                throw new SecurityException(
                        "Tool '" + tool + "' is not available in the tool registry");
            }
        }
    }

    /**
     * Case-insensitive contains check.
     */
    private boolean containsIgnoreCase(List<String> list, String value) {
        return list.stream().anyMatch(item -> item.equalsIgnoreCase(value));
    }
}
