package io.camunda.connector.sandbox.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Tool definition from the registry.
 * Matches the YAML structure in tools/registry.yaml
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ToolDefinition {

    /**
     * Tool name (e.g., "curl", "aws", "kubectl")
     */
    private String name;

    /**
     * Display name for UI
     */
    private String displayName;

    /**
     * Human-readable description
     */
    private String description;

    /**
     * Tool version
     */
    private String version;

    /**
     * Tool category (cloud, container, iac, utility)
     */
    private String category;

    /**
     * Installation method (BINARY, SYSTEM, APT, PIP)
     */
    private String installMethod;

    /**
     * URL for downloading the tool
     */
    private String installUrl;

    /**
     * Path to the binary
     */
    private String binaryPath;

    /**
     * SHA256 checksum for verification
     */
    private String checksum;

    /**
     * Allowed subcommands for the tool
     */
    private List<String> allowedSubcommands;

    /**
     * Blocked subcommands for the tool
     */
    private List<String> blockedSubcommands;

    /**
     * Allowed flags for the tool
     */
    private List<String> allowedFlags;

    /**
     * Blocked flags for the tool
     */
    private List<String> blockedFlags;

    /**
     * Whether this tool requires authentication
     */
    @Builder.Default
    private boolean requiresAuth = false;

    /**
     * Environment variables for authentication
     */
    private List<String> authEnvVars;

    /**
     * Resource limits for this tool
     */
    private ResourceLimits resourceLimits;

    /**
     * Whether network access is required
     */
    @Builder.Default
    private boolean networkAccess = false;

    /**
     * Seccomp profile name.
     * Available profiles:
     * - "default" (strict) - Most restrictive, used by default for security
     * - "permissive" - Less restrictive, required for cloud CLIs (aws, gcloud, az, terraform)
     * - "network" - For tools requiring network syscalls
     * - "strict" - Alias for "default" (for backward compatibility)
     */
    @Builder.Default
    private String seccompProfile = "default";

    /**
     * Allowed modules for scripting tools (e.g., Python).
     * These modules can be imported safely.
     */
    private List<String> allowedModules;

    /**
     * Blocked module patterns for scripting tools.
     * Any import matching these patterns will be rejected.
     */
    private List<String> blockedModulePatterns;

    // Legacy fields for backward compatibility
    /**
     * Available versions (legacy format)
     */
    private List<VersionInfo> versions;

    /**
     * Default version to use if not specified (legacy)
     */
    private String defaultVersion;

    /**
     * Whether this tool requires network access (legacy field)
     */
    @Builder.Default
    private boolean requiresNetwork = false;

    /**
     * Resource limits for a tool
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ResourceLimits {
        private int maxMemoryMb;
        private int maxCpuPercent;
        private int maxExecutionSeconds;
    }

    /**
     * Version-specific information (legacy format)
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VersionInfo {
        /**
         * Version string
         */
        private String version;

        /**
         * Installation source type (apt, pip, npm, binary)
         */
        private String source;

        /**
         * Package name in the source
         */
        private String packageName;

        /**
         * Additional packages required
         */
        private List<String> additionalPackages;

        /**
         * Download URL for binary sources
         */
        private String downloadUrl;

        /**
         * SHA256 checksum for verification
         */
        private String checksum;

        /**
         * Custom seccomp profile for this version
         */
        private String seccompProfile;

        /**
         * Binary path within the installed package
         */
        private String binaryPath;

        /**
         * Environment variables required
         */
        private Map<String, String> environment;
    }

    /**
     * Get version info for a specific version (legacy compatibility)
     */
    public VersionInfo getVersion(String requestedVersion) {
        // If using new format, create VersionInfo from current definition
        if (versions == null || versions.isEmpty()) {
            return VersionInfo.builder()
                    .version(this.version != null ? this.version : "latest")
                    .source(mapInstallMethod(this.installMethod))
                    .downloadUrl(this.installUrl)
                    .checksum(this.checksum)
                    .binaryPath(this.binaryPath)
                    .seccompProfile(this.seccompProfile)
                    .build();
        }

        // Handle "latest" version
        if ("latest".equalsIgnoreCase(requestedVersion)) {
            return versions.isEmpty() ? null : versions.get(versions.size() - 1);
        }

        return versions.stream()
                .filter(v -> v.getVersion().equals(requestedVersion))
                .findFirst()
                .orElse(null);
    }

    /**
     * Map install method to source type
     */
    private String mapInstallMethod(String installMethod) {
        if (installMethod == null) return "builtin";
        return switch (installMethod.toUpperCase()) {
            case "BINARY" -> "binary";
            case "SYSTEM" -> "builtin";
            case "APT" -> "apt";
            case "PIP" -> "pip";
            default -> "builtin";
        };
    }

    /**
     * Check if a version is available
     */
    public boolean hasVersion(String requestedVersion) {
        if ("latest".equalsIgnoreCase(requestedVersion)) {
            return true; // We always have at least the current version
        }
        if (this.version != null && this.version.equals(requestedVersion)) {
            return true;
        }
        if (versions != null) {
            return versions.stream()
                    .anyMatch(v -> v.getVersion().equals(requestedVersion));
        }
        return false;
    }

    /**
     * Check if a subcommand is allowed
     */
    public boolean isSubcommandAllowed(String subcommand) {
        // If no restrictions, allow all
        if ((allowedSubcommands == null || allowedSubcommands.isEmpty()) && 
            (blockedSubcommands == null || blockedSubcommands.isEmpty())) {
            return true;
        }

        // Check if blocked
        if (blockedSubcommands != null) {
            for (String blocked : blockedSubcommands) {
                if (subcommand.startsWith(blocked)) {
                    return false;
                }
            }
        }

        // If allowlist exists, check against it
        if (allowedSubcommands != null && !allowedSubcommands.isEmpty()) {
            for (String allowed : allowedSubcommands) {
                if (subcommand.startsWith(allowed)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    /**
     * Check if a flag is allowed
     */
    public boolean isFlagAllowed(String flag) {
        // If no restrictions, allow all
        if ((allowedFlags == null || allowedFlags.isEmpty()) && 
            (blockedFlags == null || blockedFlags.isEmpty())) {
            return true;
        }

        // Check if blocked
        if (blockedFlags != null) {
            for (String blocked : blockedFlags) {
                if (flag.startsWith(blocked)) {
                    return false;
                }
            }
        }

        // If allowlist exists, check against it
        if (allowedFlags != null && !allowedFlags.isEmpty()) {
            for (String allowed : allowedFlags) {
                if (flag.startsWith(allowed)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    /**
     * Get effective memory limit in MB
     */
    public int getMaxMemoryMb() {
        if (resourceLimits != null && resourceLimits.getMaxMemoryMb() > 0) {
            return resourceLimits.getMaxMemoryMb();
        }
        return 256; // Default
    }

    /**
     * Get effective timeout in seconds
     */
    public int getMaxExecutionSeconds() {
        if (resourceLimits != null && resourceLimits.getMaxExecutionSeconds() > 0) {
            return resourceLimits.getMaxExecutionSeconds();
        }
        return 120; // Default
    }
}
