package io.camunda.connector.sandbox.model;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Request model for sandbox CLI execution.
 * Contains all parameters from the element template.
 * 
 * Supports multiple modes:
 * 1. Direct command: provide 'command' directly
 * 2. Template mode: provide 'selectedTool' + 'commandArguments' (command is constructed)
 * 3. Capabilities mode: set 'action' to 'getCapabilities' to list available tools
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SandboxRequest {

    /**
     * Action to perform. Defaults to "execute" for normal command execution.
     * Set to "getCapabilities" to return tool capabilities without executing a command.
     * Set to "getToolHelp" with selectedTool to get help for a specific tool.
     */
    @Builder.Default
    private String action = "execute";

    /**
     * The CLI command to execute (e.g., "curl -s https://api.example.com").
     * Can be provided directly or constructed from selectedTool + commandArguments.
     */
    private String command;

    /**
     * Selected tool from the element template dropdown.
     * Used with commandArguments to construct the full command.
     */
    private String selectedTool;

    /**
     * Command arguments from the element template (without the tool name).
     * Combined with selectedTool to form the full command.
     */
    private String commandArguments;

    /**
     * List of allowed CLI tools for this execution.
     * The command's executable must be in this list.
     */
    @NotEmpty(message = "At least one allowed tool must be specified")
    private List<String> allowedTools;

    /**
     * Optional version constraints for tools (e.g., {"python3": "3.11", "curl": "latest"})
     */
    private Map<String, String> toolVersions;

    /**
     * Execution timeout in seconds (accepts String from template dropdowns)
     */
    @Builder.Default
    private String timeoutSeconds = "30";

    /**
     * Memory limit in megabytes (accepts String from template dropdowns)
     */
    @Builder.Default
    private String memoryLimitMb = "256";

    /**
     * CPU limit in millicores (1000 = 1 CPU)
     */
    @Min(value = 100, message = "CPU limit must be at least 100 millicores")
    @Builder.Default
    private int cpuLimitMillis = 1000;

    /**
     * Get the effective command, constructing it from selectedTool + commandArguments if needed.
     * If scriptContent is provided, returns null (command will be auto-generated after script file is written).
     */
    public String getEffectiveCommand() {
        // If scriptContent is provided, the command will be generated dynamically
        // after the script file is written to the workspace
        if (hasScriptContent()) {
            return null;
        }
        if (command != null && !command.isBlank()) {
            return command;
        }
        if (selectedTool != null && commandArguments != null) {
            return selectedTool + " " + commandArguments;
        }
        return command; // May be null, validation will catch it
    }

    /**
     * Check if this request uses script content mode.
     */
    public boolean hasScriptContent() {
        return scriptContent != null && !scriptContent.isBlank();
    }

    /**
     * Get the sanitized script content.
     * This method strips any wrapping quotes that FEEL expressions may have added,
     * and unescapes escape sequences.
     * 
     * For example, if FEEL returns "import json\n..." with quotes and escaped newlines,
     * this method removes the quotes and converts \n to actual newlines.
     */
    public String getScriptContent() {
        if (scriptContent == null) {
            return null;
        }
        
        String content = scriptContent.trim();
        
        // First, unescape common escape sequences that FEEL/JSON might have added
        // This must happen BEFORE stripping quotes, as the content may have escaped quotes inside
        if (content.contains("\\n") || content.contains("\\t") || content.contains("\\\"")) {
            content = content.replace("\\n", "\n")
                            .replace("\\t", "\t")
                            .replace("\\r", "\r")
                            .replace("\\\"", "\"")
                            .replace("\\'", "'")
                            .replace("\\\\", "\\");
        }
        
        // Strip wrapping double quotes if present (FEEL expression artifact)
        // Check again after unescaping
        if (content.startsWith("\"") && content.endsWith("\"") && content.length() > 2) {
            content = content.substring(1, content.length() - 1);
        }
        // Strip wrapping single quotes if present
        else if (content.startsWith("'") && content.endsWith("'") && content.length() > 2) {
            content = content.substring(1, content.length() - 1);
        }
        // Handle case where only leading quote is present (malformed, but try to fix)
        else if (content.startsWith("\"") && !content.endsWith("\"")) {
            content = content.substring(1);
        }
        else if (content.startsWith("'") && !content.endsWith("'")) {
            content = content.substring(1);
        }
        
        // Final cleanup: trim any leading/trailing whitespace that was inside quotes
        return content.trim();
    }

    /**
     * Get the effective script language, defaulting to "python" if not specified.
     */
    public String getEffectiveScriptLanguage() {
        if (scriptLanguage != null && !scriptLanguage.isBlank()) {
            return scriptLanguage.toLowerCase().trim();
        }
        return "python"; // Default to Python
    }

    /**
     * Validate the request for mutual exclusivity of command and scriptContent.
     * @throws IllegalArgumentException if both command and scriptContent are provided
     */
    public void validateMutualExclusivity() {
        boolean hasCommand = (command != null && !command.isBlank()) 
                || (selectedTool != null && commandArguments != null);
        boolean hasScript = scriptContent != null && !scriptContent.isBlank();
        
        if (hasCommand && hasScript) {
            throw new IllegalArgumentException(
                "Cannot specify both 'command' (or selectedTool/commandArguments) and 'scriptContent'. " +
                "Please use only one: either provide a command to execute, or provide script content to run.");
        }
        
        if (!hasCommand && !hasScript && !"getcapabilities".equalsIgnoreCase(action) 
                && !"gettoolhelp".equalsIgnoreCase(action)
                && !"get_capabilities".equalsIgnoreCase(action)
                && !"get_tool_help".equalsIgnoreCase(action)
                && !"capabilities".equalsIgnoreCase(action)
                && !"toolhelp".equalsIgnoreCase(action)
                && !"help".equalsIgnoreCase(action)) {
            throw new IllegalArgumentException(
                "Either 'command' (or selectedTool/commandArguments) or 'scriptContent' must be provided.");
        }
    }

    /**
     * Validate the script language if script content is provided.
     * @throws IllegalArgumentException if the script language is not supported
     */
    public void validateScriptLanguage() {
        if (hasScriptContent()) {
            String lang = getEffectiveScriptLanguage();
            if (!"python".equals(lang)) {
                throw new IllegalArgumentException(
                    "Unsupported script language: '" + lang + "'. Currently supported: python");
            }
        }
    }

    /**
     * Get timeout as integer value.
     */
    public int getTimeoutSecondsInt() {
        try {
            return timeoutSeconds != null ? Integer.parseInt(timeoutSeconds) : 30;
        } catch (NumberFormatException e) {
            return 30;
        }
    }

    /**
     * Get memory limit as integer value.
     */
    public int getMemoryLimitMbInt() {
        try {
            return memoryLimitMb != null ? Integer.parseInt(memoryLimitMb) : 256;
        } catch (NumberFormatException e) {
            return 256;
        }
    }

    /**
     * Network access mode
     */
    @Builder.Default
    private NetworkAccess networkAccess = NetworkAccess.NONE;

    /**
     * Optional working directory within the sandbox
     */
    private String workingDirectory;

    /**
     * Environment variables to inject (may include secret references)
     */
    private Map<String, String> environment;

    /**
     * Tenant ID for multi-tenant isolation
     */
    private String tenantId;

    /**
     * Input data to pass to the command (written to a file or stdin)
     */
    private String inputData;

    /**
     * Additional arguments to append to the command
     */
    private List<String> arguments;

    /**
     * Script content for multi-statement code execution.
     * When provided, the connector writes this to a temp file and executes it.
     * Cannot be used together with 'command' - they are mutually exclusive.
     * 
     * Note: A custom getter is provided that sanitizes the content (strips FEEL quotes, etc.)
     */
    @Getter(AccessLevel.NONE)
    private String scriptContent;

    /**
     * Language of the script content.
     * Currently supported: "python"
     * Defaults to "python" if not specified when scriptContent is provided.
     */
    private String scriptLanguage;

    /**
     * Network access modes
     */
    public enum NetworkAccess {
        /**
         * No network access (most secure)
         */
        NONE,
        
        /**
         * Internal network only (e.g., internal services)
         */
        INTERNAL,
        
        /**
         * External access with restrictions (allowlisted hosts only)
         */
        RESTRICTED,
        
        /**
         * Full network access (least secure, use with caution)
         */
        FULL
    }
}
