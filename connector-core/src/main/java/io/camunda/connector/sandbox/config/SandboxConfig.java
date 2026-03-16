package io.camunda.connector.sandbox.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.util.List;

/**
 * Configuration properties for the Sandbox CLI Connector.
 * Bean is registered via @EnableConfigurationProperties in SandboxConnectorApplication.
 */
@Data
@ConfigurationProperties(prefix = "sandbox")
public class SandboxConfig {

    /**
     * Whether the connector is enabled
     */
    private boolean enabled = true;

    /**
     * Path to the nsjail binary
     */
    private String nsjailPath = "/usr/bin/nsjail";

    /**
     * Base directory for sandbox workspaces
     */
    private String workspaceBase = "/sandbox/workspaces";

    /**
     * Directory containing tool installations
     */
    private String toolsDirectory = "/sandbox/tools";

    /**
     * Directory containing seccomp profiles
     */
    private String seccompProfilesDirectory = "/sandbox/seccomp";

    /**
     * Directory for sandbox root filesystem
     */
    private String sandboxRootfs = "/sandbox/rootfs";

    /**
     * Directory for temporary files
     */
    private String tempDirectory = "/sandbox/tmp";

    /**
     * Path to tenant policies configuration
     */
    private String tenantPoliciesPath = "/config/tenant-policies.yaml";

    /**
     * Path to tool registry configuration
     */
    private String toolRegistryPath = "/config/tools-registry.yaml";

    /**
     * Default tenant ID if none specified
     */
    private String defaultTenantId = "default";

    /**
     * Execution settings
     */
    private ExecutionConfig execution = new ExecutionConfig();

    /**
     * Security settings
     */
    private SecurityConfig security = new SecurityConfig();

    /**
     * Metrics settings
     */
    private MetricsConfig metrics = new MetricsConfig();

    @Data
    public static class ExecutionConfig {
        /**
         * Thread pool size for parallel executions
         */
        private int threadPoolSize = 10;

        /**
         * Maximum queue size for pending executions
         */
        private int queueSize = 100;

        /**
         * Default timeout in seconds
         */
        private int defaultTimeoutSeconds = 30;

        /**
         * Maximum timeout in seconds
         */
        private int maxTimeoutSeconds = 300;

        /**
         * Grace period after timeout before force kill (seconds)
         */
        private int gracePeriodSeconds = 5;

        /**
         * Default memory limit in MB
         */
        private int defaultMemoryMb = 256;

        /**
         * Maximum memory limit in MB
         */
        private int maxMemoryMb = 2048;

        /**
         * Default CPU limit in millicores
         */
        private int defaultCpuMillis = 1000;

        /**
         * Maximum CPU limit in millicores
         */
        private int maxCpuMillis = 4000;

        /**
         * Maximum stdout/stderr size in bytes
         */
        private int maxOutputBytes = 1048576; // 1MB
    }

    @Data
    public static class SecurityConfig {
        /**
         * Whether to enforce strict command validation
         */
        private boolean strictMode = true;

        /**
         * Whether to allow shell features (pipes, redirects, etc.)
         */
        private boolean allowShellFeatures = false;

        /**
         * Patterns to block in commands (regex)
         */
        private List<String> blockedPatterns;

        /**
         * Paths to block from access
         */
        private List<String> blockedPaths;

        /**
         * Default seccomp profile name
         */
        private String defaultSeccompProfile = "default.json";

        /**
         * Whether to drop all capabilities
         */
        private boolean dropAllCapabilities = true;

        /**
         * Whether to use user namespaces
         */
        private boolean useUserNamespace = true;

        /**
         * Whether to use network namespaces
         */
        private boolean useNetworkNamespace = true;

        /**
         * Whether to create a new PID namespace
         */
        private boolean usePidNamespace = true;

        /**
         * Whether to create a new mount namespace
         */
        private boolean useMountNamespace = true;

        /**
         * UID to run processes as inside the sandbox
         */
        private int sandboxUid = 1000;

        /**
         * GID to run processes as inside the sandbox
         */
        private int sandboxGid = 1000;
    }

    @Data
    public static class MetricsConfig {
        /**
         * Whether to collect execution metrics
         */
        private boolean enabled = true;

        /**
         * Prefix for metric names
         */
        private String prefix = "sandbox_connector";

        /**
         * Whether to include tenant tag in metrics
         */
        private boolean includeTenantTag = true;

        /**
         * Whether to include command tag in metrics (may have high cardinality)
         */
        private boolean includeCommandTag = false;
    }

    /**
     * Get the workspace path for an execution
     */
    public Path getWorkspacePath(String executionId) {
        return Path.of(workspaceBase, executionId);
    }

    /**
     * Get the path to a tool installation
     */
    public Path getToolPath(String toolName, String version) {
        return Path.of(toolsDirectory, toolName, version);
    }

    /**
     * Get the path to a seccomp profile
     */
    public Path getSeccompProfilePath(String profileName) {
        return Path.of(seccompProfilesDirectory, profileName);
    }
}
