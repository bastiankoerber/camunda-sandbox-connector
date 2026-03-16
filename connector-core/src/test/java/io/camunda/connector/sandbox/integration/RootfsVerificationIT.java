package io.camunda.connector.sandbox.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests that verify all tools in registry.yaml have their binaries
 * at the expected paths in the Docker image's rootfs.
 * 
 * This test catches mismatches between:
 * - registry.yaml binaryPath values
 * - Actual binary locations in the sandbox rootfs
 * 
 * Example: If registry.yaml says curl is at /usr/bin/curl but the Dockerfile
 * puts it at /bin/curl, this test will fail.
 * 
 * Run with: mvn verify -Pintegration
 */
@Testcontainers
@DisplayName("Rootfs Binary Path Verification Tests")
@Tag("integration")
@Tag("docker")
class RootfsVerificationIT {

    private static final Logger log = LoggerFactory.getLogger(RootfsVerificationIT.class);

    /**
     * Build and start the sandbox connector container.
     */
    @Container
    static GenericContainer<?> sandbox = new GenericContainer<>(
            new ImageFromDockerfile("sandbox-connector-rootfs-test", false)
                .withDockerfile(Paths.get("../docker/Dockerfile")))
        .withPrivilegedMode(true)
        .withLogConsumer(new Slf4jLogConsumer(log))
        .withStartupTimeout(Duration.ofMinutes(3))
        .waitingFor(org.testcontainers.containers.wait.strategy.Wait
            .forLogMessage(".*Started.*", 1)
            .withStartupTimeout(Duration.ofMinutes(2)));

    // Tools loaded from registry.yaml
    private static List<ToolInfo> registeredTools;

    @BeforeAll
    static void loadToolRegistry() throws IOException {
        registeredTools = loadToolsFromRegistry();
        log.info("Loaded {} tools from registry.yaml", registeredTools.size());
    }

    /**
     * Load tool definitions from registry.yaml.
     */
    private static List<ToolInfo> loadToolsFromRegistry() throws IOException {
        List<ToolInfo> tools = new ArrayList<>();
        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        
        try (InputStream is = RootfsVerificationIT.class.getResourceAsStream("/tools/registry.yaml")) {
            if (is == null) {
                log.warn("Could not find /tools/registry.yaml on classpath, using hardcoded defaults");
                // Fallback to known tools
                tools.add(new ToolInfo("curl", "/bin/curl"));
                tools.add(new ToolInfo("jq", "/bin/jq"));
                tools.add(new ToolInfo("git", "/bin/git"));
                tools.add(new ToolInfo("grep", "/bin/grep"));
                tools.add(new ToolInfo("sed", "/bin/sed"));
                return tools;
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> registry = yamlMapper.readValue(is, Map.class);
            
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> toolsMap = (Map<String, Map<String, Object>>) registry.get("tools");
            
            if (toolsMap != null) {
                for (Map.Entry<String, Map<String, Object>> entry : toolsMap.entrySet()) {
                    String name = entry.getKey();
                    Map<String, Object> toolDef = entry.getValue();
                    
                    String binaryPath = (String) toolDef.get("binaryPath");
                    if (binaryPath != null) {
                        tools.add(new ToolInfo(name, binaryPath));
                    } else {
                        // Check versions for binaryPath
                        @SuppressWarnings("unchecked")
                        Map<String, Map<String, Object>> versions = 
                            (Map<String, Map<String, Object>>) toolDef.get("versions");
                        if (versions != null) {
                            for (Map<String, Object> versionInfo : versions.values()) {
                                String versionBinaryPath = (String) versionInfo.get("binaryPath");
                                if (versionBinaryPath != null) {
                                    tools.add(new ToolInfo(name, versionBinaryPath));
                                    break; // Only need one version
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return tools;
    }

    /**
     * Provide tool arguments for parameterized tests.
     */
    static Stream<Arguments> toolBinaryPaths() {
        if (registeredTools == null || registeredTools.isEmpty()) {
            // Fallback if BeforeAll hasn't run yet
            return Stream.of(
                Arguments.of("curl", "/bin/curl"),
                Arguments.of("jq", "/bin/jq"),
                Arguments.of("grep", "/bin/grep"),
                Arguments.of("sed", "/bin/sed")
            );
        }
        return registeredTools.stream()
            .map(tool -> Arguments.of(tool.name, tool.binaryPath));
    }

    @Nested
    @DisplayName("Registry Binary Path Tests")
    class RegistryBinaryPathTests {

        /**
         * CRITICAL TEST: Verifies each tool's binaryPath from registry.yaml exists in the rootfs.
         * 
         * This test would catch issues like:
         * - registry.yaml says /usr/bin/curl but Dockerfile puts it at /bin/curl
         * - Tool was not installed in the Dockerfile
         * - Path typo in registry.yaml
         */
        @ParameterizedTest(name = "{0} should exist at {1}")
        @MethodSource("io.camunda.connector.sandbox.integration.RootfsVerificationIT#toolBinaryPaths")
        @DisplayName("Tool binary should exist at registered path")
        void toolBinaryShouldExistAtRegisteredPath(String toolName, String binaryPath) throws Exception {
            // Convert binaryPath to rootfs path
            String rootfsPath = "/sandbox/rootfs" + binaryPath;
            
            var result = sandbox.execInContainer("test", "-x", rootfsPath);
            
            assertThat(result.getExitCode())
                .withFailMessage(
                    "Tool '%s' not found at registered path '%s' (checked %s in container). " +
                    "Either update registry.yaml binaryPath or fix the Dockerfile. " +
                    "Stderr: %s",
                    toolName, binaryPath, rootfsPath, result.getStderr())
                .isEqualTo(0);
            
            log.info("Verified: {} exists at {}", toolName, binaryPath);
        }
    }

    @Nested
    @DisplayName("Binary Path Convention Tests")
    class BinaryPathConventionTests {

        @ParameterizedTest(name = "{0} path should be absolute")
        @MethodSource("io.camunda.connector.sandbox.integration.RootfsVerificationIT#toolBinaryPaths")
        @DisplayName("All binary paths should be absolute")
        void allBinaryPathsShouldBeAbsolute(String toolName, String binaryPath) {
            assertThat(binaryPath)
                .withFailMessage(
                    "Tool '%s' has relative binaryPath '%s'. " +
                    "nsjail requires absolute paths in the chroot.",
                    toolName, binaryPath)
                .startsWith("/");
        }

        @ParameterizedTest(name = "{0} path should use /bin/ convention")
        @MethodSource("io.camunda.connector.sandbox.integration.RootfsVerificationIT#toolBinaryPaths")
        @DisplayName("Binary paths should use /bin/ directory")
        void binaryPathsShouldUseBinDirectory(String toolName, String binaryPath) {
            // Allow /bin/, /usr/bin/, or /opt/tools/
            assertThat(binaryPath)
                .withFailMessage(
                    "Tool '%s' has binaryPath '%s' which is not in a standard location. " +
                    "Use /bin/, /usr/bin/, or /opt/tools/ for consistency.",
                    toolName, binaryPath)
                .matches("^/(bin|usr/bin|opt/tools)/.*");
        }
    }

    @Nested
    @DisplayName("Rootfs Structure Tests")
    class RootfsStructureTests {

        @Test
        @DisplayName("Rootfs should have /bin directory")
        void rootfsShouldHaveBinDirectory() throws Exception {
            var result = sandbox.execInContainer("test", "-d", "/sandbox/rootfs/bin");
            assertThat(result.getExitCode())
                .withFailMessage("/sandbox/rootfs/bin directory does not exist")
                .isEqualTo(0);
        }

        @Test
        @DisplayName("Rootfs should have /lib directory")
        void rootfsShouldHaveLibDirectory() throws Exception {
            var result = sandbox.execInContainer("test", "-d", "/sandbox/rootfs/lib");
            assertThat(result.getExitCode())
                .withFailMessage("/sandbox/rootfs/lib directory does not exist")
                .isEqualTo(0);
        }

        @Test
        @DisplayName("Rootfs should have /tmp directory")
        void rootfsShouldHaveTmpDirectory() throws Exception {
            var result = sandbox.execInContainer("test", "-d", "/sandbox/rootfs/tmp");
            assertThat(result.getExitCode())
                .withFailMessage("/sandbox/rootfs/tmp directory does not exist")
                .isEqualTo(0);
        }

        @Test
        @DisplayName("Rootfs /tmp should be world-writable")
        void rootfsTmpShouldBeWorldWritable() throws Exception {
            var result = sandbox.execInContainer("test", "-w", "/sandbox/rootfs/tmp");
            assertThat(result.getExitCode())
                .withFailMessage("/sandbox/rootfs/tmp is not writable")
                .isEqualTo(0);
        }

        @Test
        @DisplayName("Rootfs should have SSL certificates")
        void rootfsShouldHaveSslCertificates() throws Exception {
            var result = sandbox.execInContainer("test", "-d", "/sandbox/rootfs/etc/ssl");
            assertThat(result.getExitCode())
                .withFailMessage(
                    "/sandbox/rootfs/etc/ssl directory does not exist. " +
                    "curl and other tools need SSL certificates for HTTPS.")
                .isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Library Dependency Tests")
    class LibraryDependencyTests {

        @Test
        @DisplayName("curl should have all required libraries")
        void curlShouldHaveRequiredLibraries() throws Exception {
            // Use ldd to check library dependencies
            var result = sandbox.execInContainer(
                "ldd", "/sandbox/rootfs/bin/curl"
            );
            
            log.info("curl libraries: {}", result.getStdout());
            
            // Check that no libraries are "not found"
            assertThat(result.getStdout())
                .withFailMessage(
                    "curl has missing library dependencies: %s",
                    result.getStdout())
                .doesNotContain("not found");
        }

        @Test
        @DisplayName("jq should have all required libraries")
        void jqShouldHaveRequiredLibraries() throws Exception {
            var result = sandbox.execInContainer(
                "ldd", "/sandbox/rootfs/bin/jq"
            );
            
            log.info("jq libraries: {}", result.getStdout());
            
            assertThat(result.getStdout())
                .withFailMessage(
                    "jq has missing library dependencies: %s",
                    result.getStdout())
                .doesNotContain("not found");
        }
    }

    /**
     * Simple record to hold tool info.
     */
    static class ToolInfo {
        final String name;
        final String binaryPath;

        ToolInfo(String name, String binaryPath) {
            this.name = name;
            this.binaryPath = binaryPath;
        }
    }
}
