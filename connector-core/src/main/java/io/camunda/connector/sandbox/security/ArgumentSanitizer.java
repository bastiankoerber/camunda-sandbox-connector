package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.TenantPolicy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Sanitizes and validates command arguments.
 */
@Slf4j
@Component
public class ArgumentSanitizer {

    /**
     * A blocked path pattern with a user-friendly description.
     */
    private record BlockedPath(Pattern pattern, String description) {
        boolean matches(String input) {
            return pattern.matcher(input).find();
        }
    }

    // Dangerous path patterns with user-friendly descriptions
    private static final List<BlockedPath> BLOCKED_PATH_PATTERNS = List.of(
            new BlockedPath(Pattern.compile("\\.\\."), 
                "Path traversal (..) is not allowed. Please use paths within the sandbox working directory."),
            new BlockedPath(Pattern.compile("^/etc/"), 
                "Access to system configuration directory (/etc/) is not allowed."),
            new BlockedPath(Pattern.compile("^/proc/"), 
                "Access to process information (/proc/) is not allowed for security reasons."),
            new BlockedPath(Pattern.compile("^/sys/"), 
                "Access to system internals (/sys/) is not allowed."),
            new BlockedPath(Pattern.compile("^/dev/"), 
                "Access to device files (/dev/) is not allowed."),
            new BlockedPath(Pattern.compile("^/root/"), 
                "Access to root's home directory is not allowed."),
            new BlockedPath(Pattern.compile("^/home/"), 
                "Access to user home directories (/home/) is not allowed. Use the sandbox working directory instead."),
            new BlockedPath(Pattern.compile("^/var/run/"), 
                "Access to runtime data (/var/run/) is not allowed."),
            new BlockedPath(Pattern.compile("^/var/log/"), 
                "Access to system logs (/var/log/) is not allowed."),
            new BlockedPath(Pattern.compile("^/boot/"), 
                "Access to boot files (/boot/) is not allowed."),
            new BlockedPath(Pattern.compile("^/lib/"), 
                "Access to system libraries (/lib/) is not allowed."),
            new BlockedPath(Pattern.compile("^/usr/lib/"), 
                "Access to user libraries (/usr/lib/) is not allowed."),
            new BlockedPath(Pattern.compile("^/bin/"), 
                "Access to system binaries (/bin/) is not allowed. Use allowed tool names instead."),
            new BlockedPath(Pattern.compile("^/sbin/"), 
                "Access to system administration binaries (/sbin/) is not allowed."),
            new BlockedPath(Pattern.compile("^/usr/bin/"), 
                "Access to user binaries (/usr/bin/) is not allowed. Use allowed tool names instead."),
            new BlockedPath(Pattern.compile("^/usr/sbin/"), 
                "Access to user system administration binaries (/usr/sbin/) is not allowed."),
            // macOS specific paths
            new BlockedPath(Pattern.compile("^/Users/"), 
                "Access to macOS user directories (/Users/) is not allowed."),
            new BlockedPath(Pattern.compile("^/Applications/"), 
                "Access to macOS Applications directory is not allowed."),
            new BlockedPath(Pattern.compile("/Library/Keychains/"), 
                "Access to macOS Keychains is not allowed for security reasons."),
            new BlockedPath(Pattern.compile("^~"), 
                "Home directory expansion (~) is not allowed. Use explicit paths within the sandbox.")
    );

    // Maximum argument length
    private static final int MAX_ARGUMENT_LENGTH = 4096;

    // Maximum total arguments length
    private static final int MAX_TOTAL_ARGUMENTS_LENGTH = 65536;

    /**
     * Sanitize and validate a command argument.
     *
     * @param argument The argument to sanitize
     * @param toolName The tool this argument is for
     * @param tenantPolicy The tenant's security policy
     * @throws SecurityException if the argument is not safe
     */
    public void sanitize(String argument, String toolName, TenantPolicy tenantPolicy) 
            throws SecurityException {
        
        if (argument == null) {
            return;
        }

        log.debug("Sanitizing argument for tool '{}': {}", toolName, maskArgument(argument));

        // Check length
        if (argument.length() > MAX_ARGUMENT_LENGTH) {
            throw new SecurityException(
                "Argument is too long. Maximum allowed length is " + MAX_ARGUMENT_LENGTH + " characters. " +
                "Your argument has " + argument.length() + " characters. " +
                "Please reduce the size of your argument or split it into multiple commands.");
        }

        // Check for null bytes
        if (argument.contains("\0")) {
            throw new SecurityException(
                "Null bytes (\\0) are not allowed in arguments. " +
                "This character is often used in security attacks. " +
                "Please remove any null bytes from your input.");
        }

        // Check for path traversal and blocked paths
        for (BlockedPath blocked : BLOCKED_PATH_PATTERNS) {
            if (blocked.matches(argument)) {
                throw new SecurityException(blocked.description());
            }
        }

        // Check tool-specific blocked arguments
        TenantPolicy.ToolPolicy toolPolicy = tenantPolicy.getToolPolicy(toolName);
        if (toolPolicy != null && toolPolicy.getBlockedArguments() != null) {
            for (String blockedPattern : toolPolicy.getBlockedArguments()) {
                if (Pattern.compile(blockedPattern).matcher(argument).find()) {
                    throw new SecurityException(
                        "This argument is not allowed for the '" + toolName + "' tool. " +
                        "The argument matches a blocked pattern configured in your tenant policy. " +
                        "Please check with your administrator for allowed argument formats.");
                }
            }
        }

        // Check for control characters (except common whitespace)
        for (char c : argument.toCharArray()) {
            if (Character.isISOControl(c) && c != '\t' && c != '\n' && c != '\r') {
                throw new SecurityException(
                    "Control characters are not allowed in arguments. " +
                    "Your argument contains a control character (ASCII code " + (int) c + "). " +
                    "Please use only printable characters in your arguments.");
            }
        }

        log.debug("Argument sanitization passed");
    }

    /**
     * Sanitize a list of arguments.
     */
    public void sanitizeAll(List<String> arguments, String toolName, TenantPolicy tenantPolicy) 
            throws SecurityException {
        
        if (arguments == null || arguments.isEmpty()) {
            return;
        }

        // Check total length
        int totalLength = arguments.stream().mapToInt(String::length).sum();
        if (totalLength > MAX_TOTAL_ARGUMENTS_LENGTH) {
            throw new SecurityException(
                "Total arguments length exceeds the maximum allowed (" + MAX_TOTAL_ARGUMENTS_LENGTH + " characters). " +
                "Your combined arguments are " + totalLength + " characters. " +
                "Please reduce the number or size of arguments.");
        }

        // Sanitize each argument
        for (String arg : arguments) {
            sanitize(arg, toolName, tenantPolicy);
        }
    }

    /**
     * Mask argument for safe logging.
     */
    private String maskArgument(String argument) {
        if (argument == null) {
            return "[null]";
        }
        
        // Mask if looks like a secret
        String lower = argument.toLowerCase();
        if (lower.contains("password") || lower.contains("secret") || 
            lower.contains("token") || lower.contains("key") ||
            lower.contains("auth")) {
            return "[MASKED]";
        }
        
        // Truncate long arguments
        if (argument.length() > 50) {
            return argument.substring(0, 50) + "...";
        }
        
        return argument;
    }
}
