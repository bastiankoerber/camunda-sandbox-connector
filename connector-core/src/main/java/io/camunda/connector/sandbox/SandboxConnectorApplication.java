package io.camunda.connector.sandbox;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

import io.camunda.connector.sandbox.config.SandboxConfig;

/**
 * Spring Boot Application entry point for the Sandbox CLI Connector.
 * 
 * <p>This application provides a secure sandbox environment for executing
 * CLI commands within Camunda workflows. It integrates with the Camunda
 * Connector Runtime and provides enterprise-grade security features.
 * 
 * <p>Features:
 * <ul>
 *   <li>Process isolation using nsjail</li>
 *   <li>Multi-tenant security policies</li>
 *   <li>Command injection prevention</li>
 *   <li>Resource limits (CPU, memory, timeout)</li>
 *   <li>Audit logging</li>
 *   <li>Dynamic tool provisioning</li>
 * </ul>
 * 
 * @author Camunda
 * @version 1.0.0
 */
@SpringBootApplication
@EnableConfigurationProperties(SandboxConfig.class)
@EnableAsync
@ComponentScan(basePackages = {
    "io.camunda.connector.sandbox",
    "io.camunda.connector.runtime"
})
public class SandboxConnectorApplication {

    /**
     * Main entry point for the application.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(SandboxConnectorApplication.class);
        
        // Set default properties
        app.setDefaultProperties(java.util.Map.of(
            "spring.application.name", "sandbox-cli-connector",
            "server.port", "8080",
            "management.server.port", "8081",
            "management.endpoints.web.exposure.include", "health,info,metrics,prometheus"
        ));
        
        app.run(args);
    }
}
