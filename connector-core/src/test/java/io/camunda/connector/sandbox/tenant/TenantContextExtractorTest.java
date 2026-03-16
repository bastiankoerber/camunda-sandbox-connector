package io.camunda.connector.sandbox.tenant;

import io.camunda.connector.api.outbound.OutboundConnectorContext;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.SandboxRequest;
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
 * Test suite for TenantContextExtractor - tenant ID extraction.
 */
@ExtendWith(MockitoExtension.class)
class TenantContextExtractorTest {

    @Mock
    private SandboxConfig config;

    @Mock
    private OutboundConnectorContext context;

    private TenantContextExtractor tenantContextExtractor;

    @BeforeEach
    void setUp() {
        tenantContextExtractor = new TenantContextExtractor(config);
    }

    @Nested
    @DisplayName("Tenant ID from Request")
    class TenantFromRequestTests {

        @Test
        @DisplayName("Should use tenant ID from request when provided")
        void shouldUseTenantFromRequest() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("request-tenant-123")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("request-tenant-123");
        }

        @Test
        @DisplayName("Should prioritize request tenant over default")
        void shouldPrioritizeRequestTenant() {
            // When request has explicit tenant, default should not be used
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("explicit-tenant")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("explicit-tenant");
            // Verify that getDefaultTenantId was never called since request has explicit tenant
            verify(config, never()).getDefaultTenantId();
        }
    }

    @Nested
    @DisplayName("Default Tenant")
    class DefaultTenantTests {

        @Test
        @DisplayName("Should use default tenant when request has no tenant")
        void shouldUseDefaultWhenNoRequestTenant() {
            when(config.getDefaultTenantId()).thenReturn("default-tenant");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId(null)
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("default-tenant");
        }

        @Test
        @DisplayName("Should use default tenant when request tenant is blank")
        void shouldUseDefaultWhenRequestTenantBlank() {
            when(config.getDefaultTenantId()).thenReturn("default-tenant");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("   ")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("default-tenant");
        }

        @Test
        @DisplayName("Should use default tenant when request tenant is empty")
        void shouldUseDefaultWhenRequestTenantEmpty() {
            when(config.getDefaultTenantId()).thenReturn("default-tenant");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("default-tenant");
        }
    }

    @Nested
    @DisplayName("Context Handling")
    class ContextHandlingTests {

        @Test
        @DisplayName("Should handle null context gracefully")
        void shouldHandleNullContext() {
            when(config.getDefaultTenantId()).thenReturn("default-tenant");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .build();

            // Should not throw with null context
            String tenantId = tenantContextExtractor.extractTenantId(null, request);

            assertThat(tenantId).isEqualTo("default-tenant");
        }

        @Test
        @DisplayName("Should fallback to default when context extraction fails")
        void shouldFallbackWhenContextExtractionFails() {
            when(config.getDefaultTenantId()).thenReturn("fallback-tenant");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("fallback-tenant");
        }
    }

    @Nested
    @DisplayName("Tenant ID Format")
    class TenantIdFormatTests {

        @Test
        @DisplayName("Should preserve tenant ID case")
        void shouldPreserveCase() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("MyTenant-ABC123")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("MyTenant-ABC123");
        }

        @Test
        @DisplayName("Should handle special characters in tenant ID")
        void shouldHandleSpecialCharacters() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("tenant_123-abc.xyz")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("tenant_123-abc.xyz");
        }

        @Test
        @DisplayName("Should handle UUID as tenant ID")
        void shouldHandleUuidTenant() {
            String uuid = "550e8400-e29b-41d4-a716-446655440000";
            
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId(uuid)
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo(uuid);
        }

        @Test
        @DisplayName("Should handle numeric tenant ID")
        void shouldHandleNumericTenant() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("12345")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo("12345");
        }
    }

    @Nested
    @DisplayName("Multiple Calls")
    class MultipleCalls {

        @Test
        @DisplayName("Should return consistent results for same request")
        void shouldReturnConsistentResults() {
            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("consistent-tenant")
                .build();

            String tenantId1 = tenantContextExtractor.extractTenantId(context, request);
            String tenantId2 = tenantContextExtractor.extractTenantId(context, request);
            String tenantId3 = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId1).isEqualTo(tenantId2).isEqualTo(tenantId3);
        }

        @Test
        @DisplayName("Should handle different requests independently")
        void shouldHandleDifferentRequestsIndependently() {
            SandboxRequest request1 = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("tenant-1")
                .build();

            SandboxRequest request2 = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("tenant-2")
                .build();

            String tenantId1 = tenantContextExtractor.extractTenantId(context, request1);
            String tenantId2 = tenantContextExtractor.extractTenantId(context, request2);

            assertThat(tenantId1).isEqualTo("tenant-1");
            assertThat(tenantId2).isEqualTo("tenant-2");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle very long tenant ID")
        void shouldHandleLongTenantId() {
            StringBuilder longTenant = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                longTenant.append("tenant");
            }

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId(longTenant.toString())
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            assertThat(tenantId).isEqualTo(longTenant.toString());
        }

        @Test
        @DisplayName("Should handle tenant ID with only whitespace after trim")
        void shouldHandleWhitespaceOnlyTenant() {
            when(config.getDefaultTenantId()).thenReturn("default");

            SandboxRequest request = SandboxRequest.builder()
                .command("echo test")
                .allowedTools(List.of("echo"))
                .tenantId("\t\n ")
                .build();

            String tenantId = tenantContextExtractor.extractTenantId(context, request);

            // Should use default since tenant is blank after trim
            assertThat(tenantId).isEqualTo("default");
        }
    }
}
