package io.camunda.connector.sandbox.tenant;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.TenantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprehensive tests for PolicyLoader.
 * Tests tenant policy loading and management using real config objects.
 */
@DisplayName("PolicyLoader")
class PolicyLoaderTest {

    private PolicyLoader policyLoader;
    private SandboxConfig config;

    @BeforeEach
    void setUp() {
        config = new SandboxConfig();
        config.setTenantPoliciesPath(null); // Will trigger fallback to defaults
        config.setDefaultTenantId("default");
        
        policyLoader = new PolicyLoader(config);
    }

    @Nested
    @DisplayName("Initialization")
    class Initialization {

        @Test
        @DisplayName("should create policy loader without errors")
        void shouldCreatePolicyLoader() {
            assertThat(policyLoader).isNotNull();
        }
    }

    @Nested
    @DisplayName("Default policy loading")
    class DefaultPolicyLoading {

        @BeforeEach
        void loadPolicies() {
            // loadPolicies will fail to find classpath resource and fall back to defaults
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("should have at least one policy after loading defaults")
        void shouldHaveDefaultPolicy() {
            assertThat(policyLoader.getPolicyCount()).isGreaterThan(0);
        }

        @Test
        @DisplayName("default tenant should exist")
        void defaultTenantShouldExist() {
            assertThat(policyLoader.tenantExists("default")).isTrue();
        }

        @Test
        @DisplayName("default policy should be enabled")
        void defaultPolicyShouldBeEnabled() {
            TenantPolicy defaultPolicy = policyLoader.loadPolicy("default");
            
            assertThat(defaultPolicy).isNotNull();
            assertThat(defaultPolicy.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("default policy should have allowed tools")
        void defaultPolicyShouldHaveAllowedTools() {
            TenantPolicy defaultPolicy = policyLoader.loadPolicy("default");
            
            assertThat(defaultPolicy).isNotNull();
            assertThat(defaultPolicy.getAllowedTools()).isNotNull();
            assertThat(defaultPolicy.getAllowedTools()).isNotEmpty();
        }

        @Test
        @DisplayName("default policy should have resource limits")
        void defaultPolicyShouldHaveResourceLimits() {
            TenantPolicy defaultPolicy = policyLoader.loadPolicy("default");
            
            assertThat(defaultPolicy).isNotNull();
            assertThat(defaultPolicy.getResourceLimits()).isNotNull();
            assertThat(defaultPolicy.getResourceLimits().getMemoryMb()).isGreaterThan(0);
            assertThat(defaultPolicy.getResourceLimits().getTimeoutSeconds()).isGreaterThan(0);
        }
    }

    @Nested
    @DisplayName("Policy lookup")
    class PolicyLookup {

        @BeforeEach
        void loadPolicies() {
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("should return default policy for null tenant ID")
        void shouldReturnDefaultPolicyForNullTenantId() {
            TenantPolicy policy = policyLoader.loadPolicy(null);
            
            assertThat(policy).isNotNull();
        }

        @Test
        @DisplayName("should return default policy for empty tenant ID")
        void shouldReturnDefaultPolicyForEmptyTenantId() {
            TenantPolicy policy = policyLoader.loadPolicy("");
            
            assertThat(policy).isNotNull();
        }

        @Test
        @DisplayName("should return default policy for blank tenant ID")
        void shouldReturnDefaultPolicyForBlankTenantId() {
            TenantPolicy policy = policyLoader.loadPolicy("   ");
            
            assertThat(policy).isNotNull();
        }

        @Test
        @DisplayName("should fall back to default for unknown tenant")
        void shouldFallBackToDefaultForUnknownTenant() {
            TenantPolicy policy = policyLoader.loadPolicy("unknown-tenant-xyz");
            
            // Should return default policy as fallback
            assertThat(policy).isNotNull();
            assertThat(policy.getTenantId()).isEqualTo("default");
        }
    }

    @Nested
    @DisplayName("Tenant existence checking")
    class TenantExistenceChecking {

        @BeforeEach
        void loadPolicies() {
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("should correctly report tenant existence")
        void shouldReportTenantExistence() {
            assertThat(policyLoader.tenantExists("default")).isTrue();
            assertThat(policyLoader.tenantExists("nonexistent-tenant")).isFalse();
        }
    }

    @Nested
    @DisplayName("Policy reload")
    class PolicyReload {

        @Test
        @DisplayName("should reload policies successfully")
        void shouldReloadPolicies() {
            policyLoader.loadPolicies();
            int initialCount = policyLoader.getPolicyCount();
            
            policyLoader.reload();
            
            assertThat(policyLoader.getPolicyCount()).isEqualTo(initialCount);
        }
    }

    @Nested
    @DisplayName("getAllPolicies method")
    class GetAllPoliciesMethod {

        @BeforeEach
        void loadPolicies() {
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("should return immutable copy of policies")
        void shouldReturnImmutableCopy() {
            Map<String, TenantPolicy> policies = policyLoader.getAllPolicies();
            
            org.junit.jupiter.api.Assertions.assertThrows(
                    UnsupportedOperationException.class,
                    () -> policies.put("newtenant", TenantPolicy.builder().tenantId("test").build())
            );
        }

        @Test
        @DisplayName("should return all loaded policies")
        void shouldReturnAllLoadedPolicies() {
            Map<String, TenantPolicy> policies = policyLoader.getAllPolicies();
            
            assertThat(policies).isNotEmpty();
            assertThat(policies).containsKey("default");
        }
    }

    @Nested
    @DisplayName("Tool policy validation")
    class ToolPolicyValidation {

        @BeforeEach
        void loadPolicies() {
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("isToolAllowed should work correctly")
        void isToolAllowedShouldWorkCorrectly() {
            TenantPolicy policy = policyLoader.loadPolicy("default");
            
            // Default policy allows jq, yq, grep, sed, awk (from policies.yaml)
            assertThat(policy.isToolAllowed("jq")).isTrue();
            assertThat(policy.isToolAllowed("yq")).isTrue();
            assertThat(policy.isToolAllowed("grep")).isTrue();
            
            // Should not allow random tools
            assertThat(policy.isToolAllowed("random-dangerous-tool")).isFalse();
        }

        @Test
        @DisplayName("getToolPolicy should return correct policy")
        void getToolPolicyShouldReturnCorrectPolicy() {
            TenantPolicy policy = policyLoader.loadPolicy("default");
            
            TenantPolicy.ToolPolicy jqPolicy = policy.getToolPolicy("jq");
            
            assertThat(jqPolicy).isNotNull();
            assertThat(jqPolicy.getName()).isEqualToIgnoringCase("jq");
        }

        @Test
        @DisplayName("getToolPolicy should return null for non-allowed tool")
        void getToolPolicyShouldReturnNullForNonAllowedTool() {
            TenantPolicy policy = policyLoader.loadPolicy("default");
            
            TenantPolicy.ToolPolicy unknownPolicy = policy.getToolPolicy("unknown-tool");
            
            assertThat(unknownPolicy).isNull();
        }
    }

    @Nested
    @DisplayName("Version validation")
    class VersionValidation {

        @BeforeEach
        void loadPolicies() {
            policyLoader.loadPolicies();
        }

        @Test
        @DisplayName("isToolVersionAllowed should accept 'latest' when specified")
        void isToolVersionAllowedShouldAcceptLatest() {
            TenantPolicy policy = policyLoader.loadPolicy("default");
            
            assertThat(policy.isToolVersionAllowed("jq", "latest")).isTrue();
        }

        @Test
        @DisplayName("isToolVersionAllowed should return false for non-allowed tool")
        void isToolVersionAllowedShouldReturnFalseForNonAllowedTool() {
            TenantPolicy policy = policyLoader.loadPolicy("default");
            
            assertThat(policy.isToolVersionAllowed("unknown-tool", "1.0")).isFalse();
        }
    }
}
