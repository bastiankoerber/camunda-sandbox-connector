package io.camunda.connector.sandbox.tools;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ToolDefinition;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Installs and manages CLI tools for sandbox execution.
 */
@Slf4j
@Component
public class ToolInstaller {

    private final SandboxConfig config;
    private final ToolRegistry toolRegistry;
    private final Map<String, Path> installedTools = new ConcurrentHashMap<>();

    public ToolInstaller(SandboxConfig config, ToolRegistry toolRegistry) {
        this.config = config;
        this.toolRegistry = toolRegistry;
    }

    /**
     * Ensure a tool is available for execution.
     *
     * @param toolName The name of the tool
     * @param version The version to install (null for default)
     * @return Path to the tool executable
     */
    public String ensureToolAvailable(String toolName, String version) throws IOException {
        String effectiveVersion = version != null ? version : "latest";
        String cacheKey = toolName + "@" + effectiveVersion;

        // Check cache first
        if (installedTools.containsKey(cacheKey)) {
            Path cachedPath = installedTools.get(cacheKey);
            if (Files.exists(cachedPath)) {
                log.debug("Tool {} found in cache: {}", cacheKey, cachedPath);
                return cachedPath.toString();
            }
        }

        // Get tool definition
        ToolDefinition toolDef = toolRegistry.getToolDefinition(toolName);
        if (toolDef == null) {
            throw new IllegalArgumentException("Tool not found in registry: " + toolName);
        }

        ToolDefinition.VersionInfo versionInfo = toolDef.getVersion(effectiveVersion);
        if (versionInfo == null) {
            throw new IllegalArgumentException(
                    "Version " + effectiveVersion + " not found for tool: " + toolName);
        }

        // Check if already installed
        Path toolPath = getToolPath(toolName, effectiveVersion, versionInfo);
        if (Files.exists(toolPath)) {
            log.debug("Tool already installed: {}", toolPath);
            installedTools.put(cacheKey, toolPath);
            return toolPath.toString();
        }

        // Install the tool
        log.info("Installing tool: {}@{}", toolName, effectiveVersion);
        installTool(toolName, versionInfo);
        
        installedTools.put(cacheKey, toolPath);
        return toolPath.toString();
    }

    /**
     * Get the path where a tool should be installed.
     */
    private Path getToolPath(String toolName, String version, ToolDefinition.VersionInfo versionInfo) {
        if (versionInfo.getBinaryPath() != null) {
            return Path.of(versionInfo.getBinaryPath());
        }
        return config.getToolPath(toolName, version).resolve(toolName);
    }

    /**
     * Install a tool based on its source type.
     */
    private void installTool(String toolName, ToolDefinition.VersionInfo versionInfo) throws IOException {
        String source = versionInfo.getSource();
        
        switch (source) {
            case "apt" -> installFromApt(toolName, versionInfo);
            case "pip" -> installFromPip(toolName, versionInfo);
            case "binary" -> installFromBinary(toolName, versionInfo);
            case "builtin" -> {
                // Builtin tools are already available in the rootfs
                log.debug("Tool {} is builtin, no installation needed", toolName);
            }
            default -> throw new UnsupportedOperationException(
                    "Unsupported tool source: " + source);
        }
    }

    /**
     * Install a tool from apt.
     */
    private void installFromApt(String toolName, ToolDefinition.VersionInfo versionInfo) throws IOException {
        String packageName = versionInfo.getPackageName();
        if (packageName == null) {
            packageName = toolName;
        }

        log.info("Installing {} from apt package: {}", toolName, packageName);

        // In a real implementation, this would install to a specific directory
        // For now, we assume tools are pre-installed in the container
        ProcessBuilder pb = new ProcessBuilder(
                "apt-get", "install", "-y", "--no-install-recommends", packageName
        );
        pb.inheritIO();
        
        try {
            Process process = pb.start();
            boolean completed = process.waitFor(300, TimeUnit.SECONDS);
            if (!completed || process.exitValue() != 0) {
                throw new IOException("Failed to install apt package: " + packageName);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Installation interrupted", e);
        }
    }

    /**
     * Install a tool from pip.
     */
    private void installFromPip(String toolName, ToolDefinition.VersionInfo versionInfo) throws IOException {
        String packageName = versionInfo.getPackageName();
        if (packageName == null) {
            packageName = toolName;
        }

        log.info("Installing {} from pip package: {}", toolName, packageName);

        ProcessBuilder pb = new ProcessBuilder(
                "pip3", "install", "--user", packageName
        );
        pb.inheritIO();
        
        try {
            Process process = pb.start();
            boolean completed = process.waitFor(300, TimeUnit.SECONDS);
            if (!completed || process.exitValue() != 0) {
                throw new IOException("Failed to install pip package: " + packageName);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Installation interrupted", e);
        }
    }

    /**
     * Install a tool from a binary download.
     */
    private void installFromBinary(String toolName, ToolDefinition.VersionInfo versionInfo) throws IOException {
        String downloadUrl = versionInfo.getDownloadUrl();
        if (downloadUrl == null) {
            throw new IllegalArgumentException("No download URL for binary tool: " + toolName);
        }

        log.info("Installing {} from binary: {}", toolName, downloadUrl);

        Path toolDir = config.getToolPath(toolName, versionInfo.getVersion());
        Files.createDirectories(toolDir);
        Path binaryPath = toolDir.resolve(toolName);

        // Download the binary
        ProcessBuilder pb = new ProcessBuilder(
                "curl", "-fsSL", "-o", binaryPath.toString(), downloadUrl
        );
        pb.inheritIO();
        
        try {
            Process process = pb.start();
            boolean completed = process.waitFor(300, TimeUnit.SECONDS);
            if (!completed || process.exitValue() != 0) {
                throw new IOException("Failed to download binary: " + downloadUrl);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Download interrupted", e);
        }

        // Verify checksum if provided
        String expectedChecksum = versionInfo.getChecksum();
        if (expectedChecksum != null) {
            verifyChecksum(binaryPath, expectedChecksum);
        }

        // Make executable
        binaryPath.toFile().setExecutable(true);
        log.info("Installed {} to {}", toolName, binaryPath);
    }

    /**
     * Verify the checksum of a downloaded file.
     */
    private void verifyChecksum(Path filePath, String expectedChecksum) throws IOException {
        log.debug("Verifying checksum for {}", filePath);
        
        ProcessBuilder pb = new ProcessBuilder("sha256sum", filePath.toString());
        
        try {
            Process process = pb.start();
            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            if (!completed) {
                throw new IOException("Checksum verification timed out");
            }
            
            String output = new String(process.getInputStream().readAllBytes());
            String actualChecksum = output.split("\\s+")[0];
            
            // Handle checksum format with algorithm prefix
            String expected = expectedChecksum;
            if (expected.startsWith("sha256:")) {
                expected = expected.substring(7);
            }
            
            if (!actualChecksum.equalsIgnoreCase(expected)) {
                Files.delete(filePath);
                throw new SecurityException(
                        "Checksum verification failed. Expected: " + expected + ", Got: " + actualChecksum);
            }
            
            log.debug("Checksum verified for {}", filePath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Checksum verification interrupted", e);
        }
    }

    /**
     * Clear the tool cache.
     */
    public void clearCache() {
        installedTools.clear();
        log.info("Tool cache cleared");
    }
}
