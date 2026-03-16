package io.camunda.connector.sandbox.tenant;

import io.camunda.connector.api.outbound.OutboundConnectorContext;
import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.SandboxRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Extracts tenant context from connector context and request.
 */
@Slf4j
@Component
public class TenantContextExtractor {

    private final SandboxConfig config;

    public TenantContextExtractor(SandboxConfig config) {
        this.config = config;
    }

    /**
     * Extract the tenant ID from the context and request.
     * 
     * <p>Priority order:
     * <ol>
     *   <li>Explicit tenantId in request</li>
     *   <li>Zeebe job headers</li>
     *   <li>Process variables</li>
     *   <li>Default tenant</li>
     * </ol>
     *
     * @param context The connector context
     * @param request The sandbox request
     * @return The tenant ID
     */
    public String extractTenantId(OutboundConnectorContext context, SandboxRequest request) {
        // 1. Check if tenantId is explicitly set in request
        if (request.getTenantId() != null && !request.getTenantId().isBlank()) {
            log.debug("Using tenant ID from request: {}", request.getTenantId());
            return request.getTenantId();
        }

        // 2. Try to get from job headers (Camunda 8 multi-tenancy)
        try {
            // In Camunda 8, tenant info might be in the job context
            // This is a simplified implementation - actual implementation
            // depends on how Camunda 8.9+ exposes tenant information
            String tenantFromContext = extractFromJobContext(context);
            if (tenantFromContext != null && !tenantFromContext.isBlank()) {
                log.debug("Using tenant ID from job context: {}", tenantFromContext);
                return tenantFromContext;
            }
        } catch (Exception e) {
            log.debug("Could not extract tenant from job context: {}", e.getMessage());
        }

        // 3. Fall back to default tenant
        String defaultTenant = config.getDefaultTenantId();
        log.debug("Using default tenant ID: {}", defaultTenant);
        return defaultTenant;
    }

    /**
     * Extract tenant ID from job context.
     * This is a placeholder - actual implementation depends on Camunda 8.9+ API.
     */
    private String extractFromJobContext(OutboundConnectorContext context) {
        // In a real implementation, you might:
        // 1. Check job headers
        // 2. Check process variables
        // 3. Use Camunda's built-in multi-tenancy features
        
        // For now, return null to fall back to default
        return null;
    }
}
