package io.camunda.connector.sandbox.security;

import io.camunda.connector.sandbox.model.TenantPolicy;
import io.camunda.connector.sandbox.model.ToolDefinition;
import io.camunda.connector.sandbox.tools.ToolRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for AllowlistManager - tool allowlist validation.
 */
@ExtendWith(MockitoExtension.class)
class AllowlistManagerTest {

    @Mock
    private ToolRegistry toolRegistry;

    private AllowlistManager allowlistManager;

    @BeforeEach
    void setUp() {
        allowlistManager = new AllowlistManager(toolRegistry);
    }

    private TenantPolicy createPolicy(String tenantId, List<String> toolNames) {
        List<TenantPolicy.ToolPolicy> tools = toolNames.stream()
            .map(name -> TenantPolicy.ToolPolicy.builder()
                .name(name)
                .build())
            .toList();
        
        return TenantPolicy.builder()
            .tenantId(tenantId)
            .allowedTools(tools)
            .build();
    }

    @Nested
    @DisplayName("Single Tool Validation")
    class SingleToolValidationTests {

        @Test
        @DisplayName("Should allow tool in both request list and tenant policy")
        void shouldAllowToolInBothLists() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "jq"));
            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);

            assertThatCode(() -> 
                allowlistManager.validateTool("curl", List.of("curl", "jq"), policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should reject tool not in request list")
        void shouldRejectToolNotInRequestList() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "jq", "wget"));

            assertThatThrownBy(() ->
                allowlistManager.validateTool("wget", List.of("curl", "jq"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not in the list of allowed tools for this request");
        }

        @Test
        @DisplayName("Should reject tool not allowed by tenant policy")
        void shouldRejectToolNotInPolicy() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "jq"));
            // wget is in request but not in policy
            
            assertThatThrownBy(() ->
                allowlistManager.validateTool("wget", List.of("curl", "jq", "wget"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not allowed for tenant");
        }

        @Test
        @DisplayName("Should reject tool not in registry")
        void shouldRejectToolNotInRegistry() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "customtool"));
            when(toolRegistry.hasToolDefinition("customtool")).thenReturn(false);

            assertThatThrownBy(() ->
                allowlistManager.validateTool("customtool", List.of("customtool"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not available in the tool registry");
        }

        @Test
        @DisplayName("Should handle case-insensitive tool matching")
        void shouldHandleCaseInsensitiveMatching() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl"));
            when(toolRegistry.hasToolDefinition("CURL")).thenReturn(true);

            // This should work because containsIgnoreCase is used for request list
            assertThatCode(() ->
                allowlistManager.validateTool("CURL", List.of("curl"), policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should reject null request tools list")
        void shouldRejectNullRequestTools() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl"));

            assertThatThrownBy(() ->
                allowlistManager.validateTool("curl", null, policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not in the list of allowed tools");
        }
    }

    @Nested
    @DisplayName("All Tools Validation")
    class AllToolsValidationTests {

        @Test
        @DisplayName("Should validate all requested tools successfully")
        void shouldValidateAllToolsSuccessfully() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "jq", "yq"));
            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);
            when(toolRegistry.hasToolDefinition("jq")).thenReturn(true);

            assertThatCode(() ->
                allowlistManager.validateAllTools(List.of("curl", "jq"), policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should reject if any tool not allowed by policy")
        void shouldRejectIfAnyToolNotAllowed() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "jq"));
            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);
            // wget not in policy

            assertThatThrownBy(() ->
                allowlistManager.validateAllTools(List.of("curl", "wget"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("wget")
                .hasMessageContaining("not allowed for tenant");
        }

        @Test
        @DisplayName("Should reject if any tool not in registry")
        void shouldRejectIfAnyToolNotInRegistry() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "unknown"));
            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);
            when(toolRegistry.hasToolDefinition("unknown")).thenReturn(false);

            assertThatThrownBy(() ->
                allowlistManager.validateAllTools(List.of("curl", "unknown"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("unknown")
                .hasMessageContaining("not available in the tool registry");
        }

        @Test
        @DisplayName("Should reject empty tools list")
        void shouldRejectEmptyToolsList() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl"));

            assertThatThrownBy(() ->
                allowlistManager.validateAllTools(List.of(), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("At least one tool must be specified");
        }

        @Test
        @DisplayName("Should reject null tools list")
        void shouldRejectNullToolsList() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl"));

            assertThatThrownBy(() ->
                allowlistManager.validateAllTools(null, policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("At least one tool must be specified");
        }
    }

    @Nested
    @DisplayName("Version Validation")
    class VersionValidationTests {

        @Test
        @DisplayName("Should validate allowed version")
        void shouldValidateAllowedVersion() {
            List<TenantPolicy.ToolPolicy> tools = List.of(
                TenantPolicy.ToolPolicy.builder()
                    .name("python3")
                    .allowedVersions(List.of("3.11", "3.12"))
                    .build()
            );
            
            TenantPolicy policy = TenantPolicy.builder()
                .tenantId("tenant-1")
                .allowedTools(tools)
                .build();

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("python3")
                .version("3.11")
                .build();

            when(toolRegistry.getToolDefinition("python3")).thenReturn(toolDef);

            assertThatCode(() ->
                allowlistManager.validateToolVersion("python3", "3.11", policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should reject disallowed version by policy")
        void shouldRejectDisallowedVersion() {
            List<TenantPolicy.ToolPolicy> tools = List.of(
                TenantPolicy.ToolPolicy.builder()
                    .name("python3")
                    .allowedVersions(List.of("3.11"))
                    .build()
            );
            
            TenantPolicy policy = TenantPolicy.builder()
                .tenantId("tenant-1")
                .allowedTools(tools)
                .build();

            assertThatThrownBy(() ->
                allowlistManager.validateToolVersion("python3", "3.10", policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not allowed for tenant");
        }

        @Test
        @DisplayName("Should reject version not in registry")
        void shouldRejectVersionNotInRegistry() {
            List<TenantPolicy.ToolPolicy> tools = List.of(
                TenantPolicy.ToolPolicy.builder()
                    .name("python3")
                    // No version constraints - all versions allowed by policy
                    .build()
            );
            
            TenantPolicy policy = TenantPolicy.builder()
                .tenantId("tenant-1")
                .allowedTools(tools)
                .build();

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("python3")
                .version("3.11")
                .build();

            when(toolRegistry.getToolDefinition("python3")).thenReturn(toolDef);

            assertThatThrownBy(() ->
                allowlistManager.validateToolVersion("python3", "3.99", policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not available");
        }

        @Test
        @DisplayName("Should allow any version when no constraints defined")
        void shouldAllowAnyVersionWithNoConstraints() {
            List<TenantPolicy.ToolPolicy> tools = List.of(
                TenantPolicy.ToolPolicy.builder()
                    .name("curl")
                    // No allowedVersions constraint
                    .build()
            );
            
            TenantPolicy policy = TenantPolicy.builder()
                .tenantId("tenant-1")
                .allowedTools(tools)
                .build();

            ToolDefinition toolDef = ToolDefinition.builder()
                .name("curl")
                .version("7.88")
                .build();

            when(toolRegistry.getToolDefinition("curl")).thenReturn(toolDef);

            assertThatCode(() ->
                allowlistManager.validateToolVersion("curl", "7.88", policy))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Tenant Policy Tests")
    class TenantPolicyTests {

        @Test
        @DisplayName("Should use tenant ID in error messages")
        void shouldUseTenantIdInErrors() {
            TenantPolicy policy = createPolicy("my-tenant-123", List.of("curl"));

            assertThatThrownBy(() ->
                allowlistManager.validateTool("wget", List.of("wget"), policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("my-tenant-123");
        }

        @Test
        @DisplayName("Should validate tool against multiple policies")
        void shouldValidateMultiplePolicies() {
            // Test that the same tool is valid for one tenant but not another
            TenantPolicy tenant1Policy = createPolicy("tenant-1", List.of("curl", "jq"));
            TenantPolicy tenant2Policy = createPolicy("tenant-2", List.of("wget", "yq"));

            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);

            // curl allowed for tenant-1
            assertThatCode(() ->
                allowlistManager.validateTool("curl", List.of("curl"), tenant1Policy))
                .doesNotThrowAnyException();

            // curl not allowed for tenant-2
            assertThatThrownBy(() ->
                allowlistManager.validateTool("curl", List.of("curl"), tenant2Policy))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("tenant-2");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle tool name with special characters")
        void shouldHandleSpecialCharacters() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("aws-cli", "google-cloud-sdk"));
            when(toolRegistry.hasToolDefinition("aws-cli")).thenReturn(true);

            assertThatCode(() ->
                allowlistManager.validateTool("aws-cli", List.of("aws-cli"), policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle very long tool list")
        void shouldHandleLongToolList() {
            List<String> manyTools = new java.util.ArrayList<>();
            for (int i = 0; i < 100; i++) {
                manyTools.add("tool" + i);
            }

            TenantPolicy policy = createPolicy("tenant-1", manyTools);
            when(toolRegistry.hasToolDefinition("tool50")).thenReturn(true);

            assertThatCode(() ->
                allowlistManager.validateTool("tool50", manyTools, policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle duplicate tools in list")
        void shouldHandleDuplicateTools() {
            TenantPolicy policy = createPolicy("tenant-1", List.of("curl", "curl", "jq"));
            when(toolRegistry.hasToolDefinition("curl")).thenReturn(true);
            when(toolRegistry.hasToolDefinition("jq")).thenReturn(true);

            assertThatCode(() ->
                allowlistManager.validateAllTools(List.of("curl", "curl", "jq"), policy))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle whitespace in tool names")
        void shouldHandleWhitespace() {
            TenantPolicy policy = createPolicy("tenant-1", List.of(" curl ", "jq"));
            
            // Tool with whitespace shouldn't match
            assertThatThrownBy(() ->
                allowlistManager.validateTool("curl", List.of(" curl "), policy))
                .isInstanceOf(SecurityException.class);
        }
    }
}
