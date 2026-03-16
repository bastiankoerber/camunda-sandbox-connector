package io.camunda.connector.sandbox;

import io.camunda.connector.api.annotation.OutboundConnector;
import io.camunda.connector.api.outbound.OutboundConnectorContext;
import io.camunda.connector.api.outbound.OutboundConnectorFunction;
import io.camunda.connector.sandbox.audit.AuditLogger;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.execution.ExecutionOrchestrator;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.model.ToolDefinition;
import io.camunda.connector.sandbox.security.SecurityValidator;
import io.camunda.connector.sandbox.tenant.TenantContextExtractor;
import io.camunda.connector.sandbox.tools.ToolRegistry;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Camunda Outbound Connector for executing CLI commands in a secure sandbox environment.
 * 
 * <p>This connector provides:
 * <ul>
 *   <li>Secure command execution using nsjail sandboxing</li>
 *   <li>Multi-tenant isolation with per-tenant policies</li>
 *   <li>Resource limits (CPU, memory, time)</li>
 *   <li>Network isolation</li>
 *   <li>Command injection prevention</li>
 *   <li>Dynamic tool installation with allowlisting</li>
 * </ul>
 * 
 * <p>Actions:
 * <ul>
 *   <li>execute (default): Execute a CLI command in the sandbox</li>
 *   <li>getCapabilities: List all available tools and their capabilities</li>
 *   <li>getToolHelp: Get detailed help for a specific tool</li>
 * </ul>
 * 
 * <p>Security features:
 * <ul>
 *   <li>Linux namespaces (PID, Mount, Network, User, UTS)</li>
 *   <li>Seccomp-BPF syscall filtering</li>
 *   <li>Cgroups v2 resource limits</li>
 *   <li>Filesystem isolation (tmpfs, read-only mounts)</li>
 *   <li>Capability dropping</li>
 * </ul>
 */
@Slf4j
@Component
@OutboundConnector(
    name = "Sandbox CLI Executor",
    inputVariables = {
        "action",
        "command",
        "selectedTool",
        "commandArguments",
        "allowedTools", 
        "toolVersions",
        "timeoutSeconds",
        "memoryLimitMb",
        "cpuLimitMillis",
        "networkAccess",
        "workingDirectory",
        "environment",
        "tenantId",
        "inputData",
        "arguments",
        "scriptContent",
        "scriptLanguage"
    },
    type = "io.camunda:sandbox-cli:1"
)
public class SandboxCliConnector implements OutboundConnectorFunction {

    private final SecurityValidator securityValidator;
    private final ExecutionOrchestrator executionOrchestrator;
    private final TenantContextExtractor tenantContextExtractor;
    private final AuditLogger auditLogger;
    private final SandboxConfig config;
    private final ToolRegistry toolRegistry;

    public SandboxCliConnector(
            SecurityValidator securityValidator,
            ExecutionOrchestrator executionOrchestrator,
            TenantContextExtractor tenantContextExtractor,
            AuditLogger auditLogger,
            SandboxConfig config,
            ToolRegistry toolRegistry) {
        this.securityValidator = securityValidator;
        this.executionOrchestrator = executionOrchestrator;
        this.tenantContextExtractor = tenantContextExtractor;
        this.auditLogger = auditLogger;
        this.config = config;
        this.toolRegistry = toolRegistry;
    }

    @Override
    public Object execute(OutboundConnectorContext context) throws Exception {
        String executionId = UUID.randomUUID().toString();
        
        try {
            // Set up MDC for structured logging
            MDC.put("executionId", executionId);
            MDC.put("connectorType", "sandbox-cli");
            
            log.info("Starting sandbox CLI connector");
            
            // 1. Bind and validate request variables
            SandboxRequest request = context.bindVariables(SandboxRequest.class);
            
            // 2. Handle different actions
            String action = request.getAction();
            if (action == null || action.isBlank()) {
                action = "execute";
            }
            
            switch (action.toLowerCase()) {
                case "getcapabilities":
                case "get_capabilities":
                case "capabilities":
                    log.info("Returning tool capabilities");
                    return getCapabilities();
                    
                case "gettoolhelp":
                case "get_tool_help":
                case "toolhelp":
                case "help":
                    log.info("Returning help for tool: {}", request.getSelectedTool());
                    return getToolHelp(request.getSelectedTool());
                    
                case "execute":
                default:
                    return executeCommand(context, request, executionId);
            }
            
        } catch (SecurityException e) {
            log.error("Security validation failed: {}", e.getMessage());
            auditLogger.logSecurityViolation(executionId, e);
            throw e;
            
        } catch (Exception e) {
            log.error("Execution failed", e);
            auditLogger.logError(executionId, e);
            throw e;
            
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Execute a CLI command in the sandbox.
     */
    private Object executeCommand(OutboundConnectorContext context, SandboxRequest request, String executionId) throws Exception {
        // Validate mutual exclusivity of command and scriptContent
        request.validateMutualExclusivity();
        request.validateScriptLanguage();
        
        // Extract tenant context
        String tenantId = tenantContextExtractor.extractTenantId(context, request);
        request.setTenantId(tenantId);
        MDC.put("tenantId", tenantId);
        
        log.info("Processing request for tenant: {}, command: {}, hasScriptContent: {}", 
                tenantId, maskCommand(request.getEffectiveCommand()), request.hasScriptContent());
        
        // Debug: log scriptContent for troubleshooting
        if (request.hasScriptContent()) {
            String scriptContent = request.getScriptContent();
            log.debug("Script content received (length={}): first 100 chars: [{}]", 
                    scriptContent.length(), 
                    scriptContent.length() > 100 ? scriptContent.substring(0, 100) : scriptContent);
            // Check for common issues
            if (scriptContent.startsWith("\"") || scriptContent.startsWith("'")) {
                log.warn("Script content starts with a quote character - this may indicate a FEEL expression issue");
            }
        }
        
        // Validate request against security policies
        securityValidator.validate(request);
        log.debug("Security validation passed");
        
        // Execute command in sandbox
        ExecutionResult result = executionOrchestrator.execute(request, executionId);
        
        // Log audit trail
        auditLogger.logExecution(executionId, request, result);
        
        // Return result as output variables
        log.info("Execution completed: success={}, exitCode={}, durationMs={}", 
                result.isSuccess(), result.getExitCode(), result.getDurationMs());
        
        return result.toOutputVariables();
    }
    
    /**
     * Get capabilities of all available tools.
     * This allows AI agents to discover what tools are available and their restrictions.
     */
    private Map<String, Object> getCapabilities() {
        Map<String, Object> result = new HashMap<>();
        result.put("action", "getCapabilities");
        result.put("success", true);
        
        List<Map<String, Object>> toolsList = new ArrayList<>();
        
        for (Map.Entry<String, ToolDefinition> entry : toolRegistry.getAllTools().entrySet()) {
            ToolDefinition tool = entry.getValue();
            Map<String, Object> toolInfo = new HashMap<>();
            
            toolInfo.put("name", tool.getName());
            toolInfo.put("displayName", tool.getDisplayName());
            toolInfo.put("description", tool.getDescription());
            toolInfo.put("version", tool.getVersion());
            toolInfo.put("category", tool.getCategory());
            toolInfo.put("networkAccess", tool.isNetworkAccess());
            toolInfo.put("requiresAuth", tool.isRequiresAuth());
            
            // Include allowed/blocked info
            if (tool.getAllowedSubcommands() != null && !tool.getAllowedSubcommands().isEmpty()) {
                toolInfo.put("allowedSubcommands", tool.getAllowedSubcommands());
            }
            if (tool.getBlockedSubcommands() != null && !tool.getBlockedSubcommands().isEmpty()) {
                toolInfo.put("blockedSubcommands", tool.getBlockedSubcommands());
            }
            if (tool.getAllowedFlags() != null && !tool.getAllowedFlags().isEmpty()) {
                toolInfo.put("allowedFlags", tool.getAllowedFlags());
            }
            if (tool.getBlockedFlags() != null && !tool.getBlockedFlags().isEmpty()) {
                toolInfo.put("blockedFlags", tool.getBlockedFlags());
            }
            
            // Resource limits
            if (tool.getResourceLimits() != null) {
                Map<String, Object> limits = new HashMap<>();
                limits.put("maxMemoryMb", tool.getResourceLimits().getMaxMemoryMb());
                limits.put("maxCpuPercent", tool.getResourceLimits().getMaxCpuPercent());
                limits.put("maxExecutionSeconds", tool.getResourceLimits().getMaxExecutionSeconds());
                toolInfo.put("resourceLimits", limits);
            }
            
            // For scripting tools, include module info
            if ("scripting".equals(tool.getCategory())) {
                if (tool.getAllowedModules() != null) {
                    toolInfo.put("allowedModules", tool.getAllowedModules());
                }
                if (tool.getBlockedModulePatterns() != null) {
                    toolInfo.put("blockedModulePatterns", tool.getBlockedModulePatterns());
                }
                toolInfo.put("helpCommand", tool.getName() + " --help");
                toolInfo.put("capabilitiesCommand", tool.getName() + " --capabilities");
            }
            
            toolsList.add(toolInfo);
        }
        
        result.put("tools", toolsList);
        result.put("totalTools", toolsList.size());
        
        // Include usage hints for AI agents
        Map<String, String> hints = new HashMap<>();
        hints.put("execute", "Set action='execute' with command='tool_name args' to run a command");
        hints.put("getToolHelp", "Set action='getToolHelp' with selectedTool='tool_name' for detailed help");
        hints.put("pythonHelp", "For Python capabilities: command='python3 --capabilities'");
        result.put("usageHints", hints);
        
        return result;
    }
    
    /**
     * Get detailed help for a specific tool.
     */
    private Map<String, Object> getToolHelp(String toolName) {
        Map<String, Object> result = new HashMap<>();
        result.put("action", "getToolHelp");
        result.put("tool", toolName);
        
        if (toolName == null || toolName.isBlank()) {
            result.put("success", false);
            result.put("error", "No tool name provided. Set selectedTool to the tool name.");
            return result;
        }
        
        ToolDefinition tool = toolRegistry.getToolDefinition(toolName);
        if (tool == null) {
            result.put("success", false);
            result.put("error", "Tool not found: " + toolName);
            result.put("hint", "Use action='getCapabilities' to list available tools");
            return result;
        }
        
        result.put("success", true);
        result.put("name", tool.getName());
        result.put("displayName", tool.getDisplayName());
        result.put("description", tool.getDescription());
        result.put("version", tool.getVersion());
        result.put("category", tool.getCategory());
        result.put("binaryPath", tool.getBinaryPath());
        result.put("networkAccess", tool.isNetworkAccess());
        result.put("requiresAuth", tool.isRequiresAuth());
        result.put("seccompProfile", tool.getSeccompProfile());
        
        if (tool.getAllowedSubcommands() != null) {
            result.put("allowedSubcommands", tool.getAllowedSubcommands());
        }
        if (tool.getBlockedSubcommands() != null) {
            result.put("blockedSubcommands", tool.getBlockedSubcommands());
        }
        if (tool.getAllowedFlags() != null) {
            result.put("allowedFlags", tool.getAllowedFlags());
        }
        if (tool.getBlockedFlags() != null) {
            result.put("blockedFlags", tool.getBlockedFlags());
        }
        if (tool.getAuthEnvVars() != null) {
            result.put("authEnvVars", tool.getAuthEnvVars());
        }
        if (tool.getResourceLimits() != null) {
            result.put("resourceLimits", tool.getResourceLimits());
        }
        
        // For scripting tools like Python
        if ("scripting".equals(tool.getCategory())) {
            if (tool.getAllowedModules() != null) {
                result.put("allowedModules", tool.getAllowedModules());
            }
            if (tool.getBlockedModulePatterns() != null) {
                result.put("blockedModulePatterns", tool.getBlockedModulePatterns());
            }
            result.put("note", "Run '" + tool.getName() + " --help' for full documentation");
            result.put("capabilitiesJson", "Run '" + tool.getName() + " --capabilities' for JSON output");
        }
        
        return result;
    }

    /**
     * Mask sensitive parts of the command for logging.
     */
    private String maskCommand(String command) {
        if (command == null) {
            return "[null]";
        }
        // Mask potential secrets in the command
        // This is a simple implementation - the actual command is validated separately
        String masked = command;
        
        // Mask patterns that look like secrets
        masked = masked.replaceAll("(password|token|key|secret|auth)[=:][^\\s]+", "$1=***");
        masked = masked.replaceAll("Bearer [^\\s]+", "Bearer ***");
        masked = masked.replaceAll("Basic [^\\s]+", "Basic ***");
        
        // Truncate if too long
        if (masked.length() > 100) {
            masked = masked.substring(0, 100) + "...";
        }
        
        return masked;
    }
}
