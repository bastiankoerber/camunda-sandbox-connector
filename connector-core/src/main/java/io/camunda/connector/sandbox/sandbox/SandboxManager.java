package io.camunda.connector.sandbox.sandbox;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.tenant.PolicyLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Manages sandbox creation, execution, and cleanup using nsjail.
 */
@Slf4j
@Component
public class SandboxManager {

    private final SandboxConfig config;
    private final PolicyLoader policyLoader;
    private final NsjailConfigBuilder nsjailConfigBuilder;
    private final Map<String, Process> activeProcesses = new HashMap<>();

    public SandboxManager(SandboxConfig config, PolicyLoader policyLoader) {
        this.config = config;
        this.policyLoader = policyLoader;
        this.nsjailConfigBuilder = new NsjailConfigBuilder(config);
    }

    /**
     * Execute a command in a sandboxed environment.
     *
     * @param request The sandbox request
     * @param parsedCommand The parsed command
     * @param executionId Unique execution ID
     * @return The execution result
     */
    public ExecutionResult executeInSandbox(SandboxRequest request, ParsedCommand parsedCommand, String executionId) 
            throws IOException, InterruptedException {
        
        log.info("Creating sandbox for execution: {}", executionId);
        
        // Create workspace directory
        Path workspacePath = createWorkspace(executionId);
        
        try {
            // Build nsjail command using the config builder
            List<String> nsjailCommand = nsjailConfigBuilder.buildCommand(request, parsedCommand, workspacePath);
            log.debug("nsjail command: {}", String.join(" ", nsjailCommand));

            // Execute nsjail
            ProcessBuilder processBuilder = new ProcessBuilder(nsjailCommand);
            processBuilder.directory(workspacePath.toFile());
            
            // Redirect stderr to stdout for easier capture
            processBuilder.redirectErrorStream(false);
            
            // Set up environment
            Map<String, String> env = processBuilder.environment();
            env.clear();
            if (request.getEnvironment() != null) {
                env.putAll(request.getEnvironment());
            }

            Process process = processBuilder.start();
            activeProcesses.put(executionId, process);

            // Collect output
            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            
            Thread stdoutReader = new Thread(() -> readStream(process.getInputStream(), stdout));
            Thread stderrReader = new Thread(() -> readStream(process.getErrorStream(), stderr));
            stdoutReader.start();
            stderrReader.start();

            // Wait for completion with timeout
            boolean completed = process.waitFor(request.getTimeoutSecondsInt(), TimeUnit.SECONDS);
            
            stdoutReader.join(1000);
            stderrReader.join(1000);

            if (!completed) {
                process.destroyForcibly();
                return ExecutionResult.timeout(
                        executionId,
                        truncateOutput(stdout.toString()),
                        truncateOutput(stderr.toString()),
                        request.getTimeoutSecondsInt() * 1000L);
            }

            int exitCode = process.exitValue();
            boolean success = exitCode == 0;

            return ExecutionResult.builder()
                    .executionId(executionId)
                    .exitCode(exitCode)
                    .stdout(truncateOutput(stdout.toString()))
                    .stderr(truncateOutput(stderr.toString()))
                    .success(success)
                    .timedOut(false)
                    .resourceLimitExceeded(false)
                    .build();

        } finally {
            activeProcesses.remove(executionId);
            cleanupWorkspace(workspacePath);
        }
    }

    /**
     * Create a workspace directory for the execution.
     */
    private Path createWorkspace(String executionId) throws IOException {
        Path workspacePath = config.getWorkspacePath(executionId);
        Files.createDirectories(workspacePath);
        log.debug("Created workspace: {}", workspacePath);
        return workspacePath;
    }

    /**
     * Clean up a workspace directory.
     */
    private void cleanupWorkspace(Path workspacePath) {
        try {
            if (Files.exists(workspacePath)) {
                Files.walk(workspacePath)
                        .sorted(Comparator.reverseOrder())
                        .forEach(path -> {
                            try {
                                Files.delete(path);
                            } catch (IOException e) {
                                log.warn("Failed to delete {}: {}", path, e.getMessage());
                            }
                        });
                log.debug("Cleaned up workspace: {}", workspacePath);
            }
        } catch (IOException e) {
            log.warn("Failed to cleanup workspace {}: {}", workspacePath, e.getMessage());
        }
    }

    /**
     * Force cleanup a specific execution.
     */
    public void forceCleanup(String executionId) {
        Process process = activeProcesses.remove(executionId);
        if (process != null && process.isAlive()) {
            log.warn("Force killing process for execution: {}", executionId);
            process.destroyForcibly();
        }
        
        Path workspacePath = config.getWorkspacePath(executionId);
        cleanupWorkspace(workspacePath);
    }

    /**
     * Read a stream into a StringBuilder.
     */
    private void readStream(InputStream inputStream, StringBuilder output) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            int maxLines = 10000;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < maxLines) {
                output.append(line).append("\n");
                lineCount++;
            }
            if (lineCount >= maxLines) {
                output.append("\n[Output truncated after ").append(maxLines).append(" lines]");
            }
        } catch (IOException e) {
            log.warn("Error reading stream: {}", e.getMessage());
        }
    }

    /**
     * Truncate output to configured maximum size.
     */
    private String truncateOutput(String output) {
        int maxSize = config.getExecution().getMaxOutputBytes();
        if (output.length() > maxSize) {
            return output.substring(0, maxSize) + "\n[Output truncated]";
        }
        return output;
    }
}
