package io.camunda.connector.sandbox.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Tenant-specific security policy defining allowed tools, limits, and network access.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TenantPolicy {

    /**
     * Unique tenant identifier
     */
    private String tenantId;

    /**
     * Human-readable tenant name
     */
    private String tenantName;

    /**
     * Whether the tenant is enabled
     */
    @Builder.Default
    private boolean enabled = true;

    /**
     * List of tools allowed for this tenant
     */
    private List<ToolPolicy> allowedTools;

    /**
     * Resource limits for this tenant
     */
    private ResourceLimits resourceLimits;

    /**
     * Network policy for this tenant
     */
    private NetworkPolicy networkPolicy;

    /**
     * Secret mappings for this tenant
     */
    private List<SecretMapping> secrets;

    /**
     * Policy for a specific tool
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ToolPolicy {
        /**
         * Tool name (e.g., "curl", "python3")
         */
        private String name;

        /**
         * Allowed versions (e.g., ["3.11", "3.12"] or ["latest"])
         */
        private List<String> allowedVersions;

        /**
         * Whether network access is allowed for this tool
         */
        @Builder.Default
        private boolean networkAllowed = false;

        /**
         * Blocked argument patterns (regex)
         */
        private List<String> blockedArguments;

        /**
         * Custom seccomp profile name
         */
        private String seccompProfile;
    }

    /**
     * Resource limits for tenant executions
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceLimits {
        /**
         * CPU limit in millicores (1000 = 1 CPU)
         */
        @Builder.Default
        private int cpuMillis = 1000;

        /**
         * Memory limit in megabytes
         */
        @Builder.Default
        private int memoryMb = 256;

        /**
         * Execution timeout in seconds
         */
        @Builder.Default
        private int timeoutSeconds = 60;

        /**
         * Maximum concurrent executions
         */
        @Builder.Default
        private int maxConcurrent = 5;

        /**
         * Maximum stdout/stderr output size in bytes
         */
        @Builder.Default
        private int maxOutputBytes = 1048576; // 1MB

        /**
         * Maximum number of file descriptors
         */
        @Builder.Default
        private int maxFileDescriptors = 64;

        /**
         * Maximum number of processes/threads
         */
        @Builder.Default
        private int maxProcesses = 10;
    }

    /**
     * Network policy configuration
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NetworkPolicy {
        /**
         * Whether egress network access is allowed
         */
        @Builder.Default
        private boolean egressAllowed = false;

        /**
         * Allowlisted hosts for egress (glob patterns)
         */
        private List<String> allowedHosts;

        /**
         * Blocked hosts (takes precedence over allowed)
         */
        private List<String> blockedHosts;

        /**
         * Allowed ports
         */
        private List<Integer> allowedPorts;

        /**
         * Whether DNS resolution is allowed
         */
        @Builder.Default
        private boolean dnsAllowed = false;
    }

    /**
     * Secret mapping configuration
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SecretMapping {
        /**
         * Environment variable name to inject
         */
        private String envName;

        /**
         * Source type (k8s-secret, vault, etc.)
         */
        private String source;

        /**
         * Secret name in the source
         */
        private String secretName;

        /**
         * Key within the secret
         */
        private String secretKey;
    }

    /**
     * Check if a tool is allowed for this tenant
     */
    public boolean isToolAllowed(String toolName) {
        if (allowedTools == null) {
            return false;
        }
        return allowedTools.stream()
                .anyMatch(tool -> tool.getName().equalsIgnoreCase(toolName));
    }

    /**
     * Get the policy for a specific tool
     */
    public ToolPolicy getToolPolicy(String toolName) {
        if (allowedTools == null) {
            return null;
        }
        return allowedTools.stream()
                .filter(tool -> tool.getName().equalsIgnoreCase(toolName))
                .findFirst()
                .orElse(null);
    }

    /**
     * Check if a tool version is allowed
     */
    public boolean isToolVersionAllowed(String toolName, String version) {
        ToolPolicy policy = getToolPolicy(toolName);
        if (policy == null) {
            return false;
        }
        if (policy.getAllowedVersions() == null || policy.getAllowedVersions().isEmpty()) {
            return true; // No version restriction
        }
        return policy.getAllowedVersions().contains(version) ||
               policy.getAllowedVersions().contains("latest") ||
               policy.getAllowedVersions().contains("*");
    }
}
