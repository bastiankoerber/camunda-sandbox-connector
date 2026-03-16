package io.camunda.connector.sandbox.tenant;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.TenantPolicy;
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
 * Loads and manages tenant security policies.
 */
@Slf4j
@Component
public class PolicyLoader {

    private final SandboxConfig config;
    private final ObjectMapper yamlMapper;
    private final Map<String, TenantPolicy> policies = new ConcurrentHashMap<>();

    public PolicyLoader(SandboxConfig config) {
        this.config = config;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        this.yamlMapper.findAndRegisterModules();
    }

    @PostConstruct
    public void init() {
        loadPolicies();
    }

    /**
     * Load tenant policies from configuration.
     */
    public void loadPolicies() {
        // First try external file path
        String policiesPath = config.getTenantPoliciesPath();
        if (policiesPath != null && !policiesPath.isBlank()) {
            File policiesFile = new File(policiesPath);
            if (policiesFile.exists()) {
                try {
                    loadFromFile(policiesFile);
                    return;
                } catch (IOException e) {
                    log.warn("Failed to load tenant policies from {}: {}", policiesPath, e.getMessage());
                }
            }
        }

        // Fall back to classpath resource
        try {
            loadFromClasspath();
        } catch (IOException e) {
            log.error("Failed to load tenant policies from classpath: {}", e.getMessage());
            loadDefaultPolicy();
        }
    }

    /**
     * Load from external file.
     */
    private void loadFromFile(File policiesFile) throws IOException {
        log.info("Loading tenant policies from file: {}", policiesFile.getAbsolutePath());
        TenantPoliciesConfig policiesConfig = yamlMapper.readValue(policiesFile, TenantPoliciesConfig.class);
        processPoliciesConfig(policiesConfig);
    }

    /**
     * Load from classpath resource.
     */
    private void loadFromClasspath() throws IOException {
        log.info("Loading tenant policies from classpath");
        ClassPathResource resource = new ClassPathResource("tenant/policies.yaml");
        try (InputStream is = resource.getInputStream()) {
            TenantPoliciesConfig policiesConfig = yamlMapper.readValue(is, TenantPoliciesConfig.class);
            processPoliciesConfig(policiesConfig);
        }
    }

    /**
     * Process the policies configuration.
     */
    private void processPoliciesConfig(TenantPoliciesConfig policiesConfig) {
        if (policiesConfig.getTenants() != null) {
            for (TenantPolicy policy : policiesConfig.getTenants()) {
                policies.put(policy.getTenantId(), policy);
                log.info("Loaded policy for tenant: {} (enabled={})", 
                        policy.getTenantId(), policy.isEnabled());
            }
        }
        log.info("Loaded {} tenant policies", policies.size());
    }

    /**
     * Load a default policy for development/testing.
     */
    private void loadDefaultPolicy() {
        log.info("Loading default tenant policy");

        TenantPolicy defaultPolicy = TenantPolicy.builder()
                .tenantId("default")
                .tenantName("Default Tenant")
                .enabled(true)
                .allowedTools(List.of(
                        TenantPolicy.ToolPolicy.builder()
                                .name("jq")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(false)
                                .seccompProfile("strict")
                                .build(),
                        TenantPolicy.ToolPolicy.builder()
                                .name("yq")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(false)
                                .seccompProfile("strict")
                                .build(),
                        TenantPolicy.ToolPolicy.builder()
                                .name("grep")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(false)
                                .seccompProfile("strict")
                                .build(),
                        TenantPolicy.ToolPolicy.builder()
                                .name("curl")
                                .allowedVersions(List.of("latest"))
                                .networkAllowed(true)
                                .seccompProfile("network")
                                .build()
                ))
                .resourceLimits(TenantPolicy.ResourceLimits.builder()
                        .cpuMillis(1000)
                        .memoryMb(256)
                        .timeoutSeconds(60)
                        .maxConcurrent(5)
                        .maxOutputBytes(1048576)
                        .maxFileDescriptors(64)
                        .maxProcesses(16)
                        .build())
                .networkPolicy(TenantPolicy.NetworkPolicy.builder()
                        .egressAllowed(false)
                        .dnsAllowed(false)
                        .build())
                .build();

        policies.put("default", defaultPolicy);
        log.info("Loaded default tenant policy");
    }

    /**
     * Load policy for a specific tenant.
     */
    public TenantPolicy loadPolicy(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            tenantId = config.getDefaultTenantId();
        }

        TenantPolicy policy = policies.get(tenantId);
        if (policy == null) {
            // Fall back to default if tenant-specific policy not found
            policy = policies.get("default");
            if (policy != null) {
                log.debug("Using default policy for tenant: {}", tenantId);
            }
        }

        return policy;
    }

    /**
     * Get all loaded policies.
     */
    public Map<String, TenantPolicy> getAllPolicies() {
        return Map.copyOf(policies);
    }

    /**
     * Reload policies from configuration.
     */
    public void reload() {
        policies.clear();
        loadPolicies();
    }

    /**
     * Check if a tenant exists.
     */
    public boolean tenantExists(String tenantId) {
        return policies.containsKey(tenantId);
    }

    /**
     * Get the number of loaded policies.
     */
    public int getPolicyCount() {
        return policies.size();
    }

    /**
     * Configuration model for the policies YAML file.
     */
    @Data
    public static class TenantPoliciesConfig {
        private List<TenantPolicy> tenants;
        private GlobalSettings globalSettings;
    }

    /**
     * Global settings configuration.
     */
    @Data
    public static class GlobalSettings {
        private TenantPolicy.ResourceLimits absoluteLimits;
        private DefaultSettings defaults;
        private AuditSettings audit;
    }

    /**
     * Default settings for new tenants.
     */
    @Data
    public static class DefaultSettings {
        private boolean enabled;
        private TenantPolicy.ResourceLimits resourceLimits;
        private TenantPolicy.NetworkPolicy networkPolicy;
    }

    /**
     * Audit settings.
     */
    @Data
    public static class AuditSettings {
        private boolean logAllCommands;
        private boolean logCommandArguments;
        private boolean maskSecrets;
        private int retentionDays;
    }
}
