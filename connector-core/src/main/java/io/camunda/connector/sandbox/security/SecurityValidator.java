package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.model.TenantPolicy;
import io.camunda.connector.sandbox.tenant.PolicyLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Main security validator that orchestrates all security checks.
 * This is the critical security gate that all requests must pass through.
 */
@Slf4j
@Component
public class SecurityValidator {

    private final CommandParser commandParser;
    private final InjectionDetector injectionDetector;
    private final AllowlistManager allowlistManager;
    private final ArgumentSanitizer argumentSanitizer;
    private final PolicyLoader policyLoader;
    private final SandboxConfig config;

    public SecurityValidator(
            CommandParser commandParser,
            InjectionDetector injectionDetector,
            AllowlistManager allowlistManager,
            ArgumentSanitizer argumentSanitizer,
            PolicyLoader policyLoader,
            SandboxConfig config) {
        this.commandParser = commandParser;
        this.injectionDetector = injectionDetector;
        this.allowlistManager = allowlistManager;
        this.argumentSanitizer = argumentSanitizer;
        this.policyLoader = policyLoader;
        this.config = config;
    }

    /**
     * Validate a sandbox request against all security policies.
     * 
     * @param request The request to validate
     * @throws SecurityException if validation fails
     */
    public void validate(SandboxRequest request) throws SecurityException {
        log.debug("Starting security validation for tenant: {}", request.getTenantId());

        // 1. Load tenant policy
        TenantPolicy tenantPolicy = policyLoader.loadPolicy(request.getTenantId());
        if (tenantPolicy == null) {
            throw new SecurityException("No policy found for tenant: " + request.getTenantId());
        }
        if (!tenantPolicy.isEnabled()) {
            throw new SecurityException("Tenant is disabled: " + request.getTenantId());
        }

        // 2. Handle script mode vs command mode
        if (request.hasScriptContent()) {
            validateScriptMode(request, tenantPolicy);
        } else {
            validateCommandMode(request, tenantPolicy);
        }

        // 3. Validate resource limits against policy (common to both modes)
        validateResourceLimits(request, tenantPolicy);
        log.debug("Resource limit validation passed");

        // 4. Validate environment variables (common to both modes)
        if (request.getEnvironment() != null) {
            validateEnvironment(request.getEnvironment(), tenantPolicy);
        }
        log.debug("Environment validation passed");

        log.info("Security validation completed successfully");
    }

    /**
     * Validate script mode requests (scriptContent provided).
     * In script mode, the command is auto-generated as "safe-python3 /workspace/script.py"
     */
    private void validateScriptMode(SandboxRequest request, TenantPolicy tenantPolicy) throws SecurityException {
        log.debug("Validating script mode request");

        // Validate that safe-python3 is in the allowed tools list
        String scriptTool = "safe-python3";
        allowlistManager.validateTool(scriptTool, request.getAllowedTools(), tenantPolicy);
        log.debug("Script tool allowlist validation passed");

        // Validate script language is supported
        String lang = request.getEffectiveScriptLanguage();
        if (!"python".equals(lang)) {
            throw new SecurityException("Unsupported script language: " + lang + ". Only 'python' is currently supported.");
        }
        log.debug("Script language validation passed");

        // Validate network access for script execution
        validateNetworkAccess(request, scriptTool, tenantPolicy);
        log.debug("Network access validation passed for script mode");

        // Note: The script content itself is not checked for injection here because:
        // 1. It's written to a file and executed by safe-python3
        // 2. safe-python3 has its own security (blocked modules like os, subprocess, socket)
        // 3. The sandbox (nsjail) provides the ultimate containment
        log.debug("Script mode validation completed");
    }

    /**
     * Validate command mode requests (command or selectedTool+commandArguments provided).
     */
    private void validateCommandMode(SandboxRequest request, TenantPolicy tenantPolicy) throws SecurityException {
        log.debug("Validating command mode request");

        String effectiveCommand = request.getEffectiveCommand();
        if (effectiveCommand == null || effectiveCommand.isBlank()) {
            throw new SecurityException("Command cannot be empty in command mode");
        }

        // Check for injection attempts in raw command
        injectionDetector.detectInjection(effectiveCommand);
        log.debug("Injection detection passed");

        // Parse the command
        ParsedCommand parsedCommand = commandParser.parse(effectiveCommand);
        log.debug("Command parsed: executable={}", parsedCommand.getExecutable());

        // Validate executable against allowlist
        allowlistManager.validateTool(
                parsedCommand.getExecutable(),
                request.getAllowedTools(),
                tenantPolicy
        );
        log.debug("Allowlist validation passed");

        // Validate tool version if specified
        if (request.getToolVersions() != null) {
            String version = request.getToolVersions().get(parsedCommand.getExecutable());
            if (version != null) {
                allowlistManager.validateToolVersion(
                        parsedCommand.getExecutable(),
                        version,
                        tenantPolicy
                );
            }
        }

        // Sanitize and validate arguments
        for (String arg : parsedCommand.getArguments()) {
            argumentSanitizer.sanitize(arg, parsedCommand.getExecutable(), tenantPolicy);
        }
        log.debug("Argument sanitization passed");

        // Validate network access
        validateNetworkAccess(request, parsedCommand.getExecutable(), tenantPolicy);
        log.debug("Network access validation passed");
    }

    /**
     * Validate that requested resource limits are within policy bounds.
     */
    private void validateResourceLimits(SandboxRequest request, TenantPolicy tenantPolicy) {
        TenantPolicy.ResourceLimits limits = tenantPolicy.getResourceLimits();
        if (limits == null) {
            return; // No limits defined
        }

        // Check timeout
        if (request.getTimeoutSecondsInt() > limits.getTimeoutSeconds()) {
            throw new SecurityException(String.format(
                    "Requested timeout (%ds) exceeds maximum allowed (%ds)",
                    request.getTimeoutSecondsInt(), limits.getTimeoutSeconds()));
        }

        // Check memory
        if (request.getMemoryLimitMbInt() > limits.getMemoryMb()) {
            throw new SecurityException(String.format(
                    "Requested memory (%dMB) exceeds maximum allowed (%dMB)",
                    request.getMemoryLimitMbInt(), limits.getMemoryMb()));
        }

        // Check CPU
        if (request.getCpuLimitMillis() > limits.getCpuMillis()) {
            throw new SecurityException(String.format(
                    "Requested CPU (%dm) exceeds maximum allowed (%dm)",
                    request.getCpuLimitMillis(), limits.getCpuMillis()));
        }

        // Also validate against global config limits
        if (request.getTimeoutSecondsInt() > config.getExecution().getMaxTimeoutSeconds()) {
            throw new SecurityException(String.format(
                    "Requested timeout (%ds) exceeds system maximum (%ds)",
                    request.getTimeoutSecondsInt(), config.getExecution().getMaxTimeoutSeconds()));
        }

        if (request.getMemoryLimitMbInt() > config.getExecution().getMaxMemoryMb()) {
            throw new SecurityException(String.format(
                    "Requested memory (%dMB) exceeds system maximum (%dMB)",
                    request.getMemoryLimitMbInt(), config.getExecution().getMaxMemoryMb()));
        }
    }

    /**
     * Validate network access against policy.
     */
    private void validateNetworkAccess(SandboxRequest request, String tool, TenantPolicy tenantPolicy) {
        if (request.getNetworkAccess() == SandboxRequest.NetworkAccess.NONE) {
            return; // No network access requested
        }

        // Check tenant network policy
        TenantPolicy.NetworkPolicy networkPolicy = tenantPolicy.getNetworkPolicy();
        if (networkPolicy == null || !networkPolicy.isEgressAllowed()) {
            if (request.getNetworkAccess() != SandboxRequest.NetworkAccess.NONE) {
                throw new SecurityException(
                        "Network access is not allowed for tenant: " + request.getTenantId());
            }
        }

        // Check tool-specific network policy
        TenantPolicy.ToolPolicy toolPolicy = tenantPolicy.getToolPolicy(tool);
        if (toolPolicy != null && !toolPolicy.isNetworkAllowed()) {
            if (request.getNetworkAccess() != SandboxRequest.NetworkAccess.NONE) {
                throw new SecurityException(
                        "Network access is not allowed for tool: " + tool);
            }
        }
    }

    /**
     * Validate environment variables don't contain dangerous values.
     */
    private void validateEnvironment(java.util.Map<String, String> environment, TenantPolicy tenantPolicy) {
        for (var entry : environment.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();

            // Check for dangerous environment variable names
            if (isDangerousEnvVar(name)) {
                throw new SecurityException("Dangerous environment variable: " + name);
            }

            // Check for injection in values
            injectionDetector.detectInjection(value);
        }
    }

    /**
     * Check if an environment variable name is potentially dangerous.
     */
    private boolean isDangerousEnvVar(String name) {
        String upper = name.toUpperCase();
        
        // Linux: Library preloading and linker manipulation (can inject malicious code)
        if (upper.equals("LD_PRELOAD") || upper.equals("LD_LIBRARY_PATH") ||
            upper.equals("LD_AUDIT") || upper.equals("LD_DEBUG") ||
            upper.equals("LD_PROFILE") || upper.equals("LD_SHOW_AUXV") ||
            upper.equals("LD_BIND_NOW") || upper.equals("LD_BIND_NOT") ||
            upper.equals("LD_TRACE_LOADED_OBJECTS") || upper.equals("LD_DEBUG_OUTPUT") ||
            upper.equals("LD_ORIGIN_PATH") || upper.equals("LD_ASSUME_KERNEL") ||
            upper.equals("LD_DYNAMIC_WEAK") || upper.equals("LD_POINTER_GUARD") ||
            upper.equals("LD_USE_LOAD_BIAS") || upper.equals("LD_HWCAP_MASK") ||
            upper.startsWith("LD_")) {  // Block ALL LD_* variables to be safe
            return true;
        }
        
        // macOS: DYLD library injection
        if (upper.startsWith("DYLD_")) {
            return true;
        }
        
        // Shell environment manipulation
        if (upper.startsWith("BASH_") || upper.equals("IFS") || upper.equals("PATH") ||
            upper.equals("HOME") || upper.equals("USER") || upper.equals("SHELL") ||
            upper.equals("PROMPT_COMMAND") || upper.equals("PS1") || upper.equals("PS2") ||
            upper.equals("PS4") || upper.equals("ENV") || upper.equals("BASH_ENV") ||
            upper.equals("CDPATH") || upper.equals("GLOBIGNORE") || upper.equals("SHELLOPTS")) {
            return true;
        }
        
        // Scripting language path manipulation
        if (upper.equals("PYTHONPATH") || upper.equals("PYTHONSTARTUP") || upper.equals("PYTHONHOME") ||
            upper.equals("RUBYLIB") || upper.equals("RUBYOPT") || upper.equals("GEM_PATH") ||
            upper.equals("PERL5LIB") || upper.equals("PERLLIB") || upper.equals("PERL5OPT") ||
            upper.equals("NODE_PATH") || upper.equals("NODE_OPTIONS") ||
            upper.equals("CLASSPATH") || upper.equals("JAVA_TOOL_OPTIONS") || upper.equals("JAVA_OPTS") ||
            upper.equals("_JAVA_OPTIONS")) {
            return true;
        }
        
        // Proxy settings (could redirect traffic to malicious servers)
        if (upper.equals("HTTP_PROXY") || upper.equals("HTTPS_PROXY") ||
            upper.equals("FTP_PROXY") || upper.equals("ALL_PROXY") ||
            upper.equals("NO_PROXY") || upper.equals("http_proxy") ||
            upper.equals("https_proxy")) {
            return true;
        }
        
        // Editor/pager (could execute arbitrary commands)
        if (upper.equals("EDITOR") || upper.equals("VISUAL") || upper.equals("PAGER") ||
            upper.equals("LESS") || upper.equals("LESSOPEN") || upper.equals("LESSCLOSE") ||
            upper.equals("MANPAGER")) {
            return true;
        }
        
        // Git hooks and config (could execute commands)
        if (upper.startsWith("GIT_") && (upper.contains("EXEC") || upper.contains("HOOK") ||
            upper.contains("EDITOR") || upper.contains("SSH_COMMAND"))) {
            return true;
        }
        
        // Terminal control (could be used for escape sequence attacks)
        if (upper.equals("TERM") || upper.equals("TERMCAP") || upper.equals("TERMINFO") ||
            upper.equals("COLORTERM")) {
            return true;
        }
        
        // Locale settings (can cause unexpected behavior)
        if (upper.equals("LOCPATH") || upper.equals("NLSPATH")) {
            return true;
        }
        
        // Temporary directory manipulation
        if (upper.equals("TMPDIR") || upper.equals("TMP") || upper.equals("TEMP")) {
            return true;
        }
        
        return false;
    }
}
