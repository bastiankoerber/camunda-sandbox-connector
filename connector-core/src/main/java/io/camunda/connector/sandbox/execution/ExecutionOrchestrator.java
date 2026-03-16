package io.camunda.connector.sandbox.execution;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ExecutionResult;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import io.camunda.connector.sandbox.sandbox.SandboxManager;
import io.camunda.connector.sandbox.security.CommandParser;
import io.camunda.connector.sandbox.tools.ToolInstaller;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * Orchestrates the execution of commands in sandboxed environments.
 */
@Slf4j
@Component
public class ExecutionOrchestrator {

    private final SandboxManager sandboxManager;
    private final ToolInstaller toolInstaller;
    private final CommandParser commandParser;
    private final SandboxConfig config;
    private final MeterRegistry meterRegistry;
    private final ExecutorService executorService;
    private final Semaphore concurrencyLimiter;

    public ExecutionOrchestrator(
            SandboxManager sandboxManager,
            ToolInstaller toolInstaller,
            CommandParser commandParser,
            SandboxConfig config,
            MeterRegistry meterRegistry) {
        this.sandboxManager = sandboxManager;
        this.toolInstaller = toolInstaller;
        this.commandParser = commandParser;
        this.config = config;
        this.meterRegistry = meterRegistry;
        
        // Create bounded thread pool
        int poolSize = config.getExecution().getThreadPoolSize();
        this.executorService = new ThreadPoolExecutor(
                poolSize,
                poolSize,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(config.getExecution().getQueueSize()),
                new ThreadPoolExecutor.AbortPolicy()
        );
        
        // Concurrency limiter for backpressure
        this.concurrencyLimiter = new Semaphore(poolSize * 2);
    }

    /**
     * Execute a command in a sandbox.
     *
     * @param request The sandbox request
     * @param executionId Unique execution ID
     * @return The execution result
     */
    public ExecutionResult execute(SandboxRequest request, String executionId) {
        Instant startTime = Instant.now();
        Timer.Sample timerSample = Timer.start(meterRegistry);

        try {
            // Acquire permit (with timeout)
            if (!concurrencyLimiter.tryAcquire(30, TimeUnit.SECONDS)) {
                return ExecutionResult.failure(
                        executionId, -1, "", "",
                        0, "System overloaded - too many concurrent executions");
            }

            try {
                return executeInternal(request, executionId, startTime);
            } finally {
                concurrencyLimiter.release();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ExecutionResult.failure(
                    executionId, -1, "", "",
                    System.currentTimeMillis() - startTime.toEpochMilli(),
                    "Execution interrupted");
        } finally {
            // Record metrics
            timerSample.stop(Timer.builder("sandbox.execution.duration")
                    .tag("tenant", request.getTenantId() != null ? request.getTenantId() : "unknown")
                    .register(meterRegistry));
        }
    }

    /**
     * Internal execution logic.
     */
    private ExecutionResult executeInternal(SandboxRequest request, String executionId, Instant startTime) {
        log.info("Starting execution {}: hasScriptContent={}, command={}", 
                executionId, request.hasScriptContent(), maskCommand(request.getEffectiveCommand()));

        Path scriptFilePath = null;
        
        try {
            String effectiveCommand;
            
            // Handle scriptContent mode
            if (request.hasScriptContent()) {
                // Generate unique script filename
                String scriptId = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
                String extension = getScriptExtension(request.getEffectiveScriptLanguage());
                String scriptFileName = "script_" + scriptId + extension;
                
                // Create workspace directory if needed for script file
                Path workspacePath = config.getWorkspacePath(executionId);
                Files.createDirectories(workspacePath);
                scriptFilePath = workspacePath.resolve(scriptFileName);
                
                // Get sanitized script content
                String scriptContent = request.getScriptContent();
                
                // Debug logging to diagnose FEEL encoding issues
                log.info("Script content (first 200 chars): [{}]", 
                        scriptContent.length() > 200 ? scriptContent.substring(0, 200) : scriptContent);
                log.debug("Script content full length: {} chars", scriptContent.length());
                
                // Write script content to file
                log.debug("Writing script content to: {}", scriptFilePath);
                Files.writeString(scriptFilePath, scriptContent, StandardCharsets.UTF_8);
                
                // Generate the command based on script language
                String toolName = getToolForLanguage(request.getEffectiveScriptLanguage());
                // Use /workspace path since that's where nsjail mounts the workspace
                effectiveCommand = toolName + " /workspace/" + scriptFileName;
                
                log.info("Generated command for script execution: {}", effectiveCommand);
            } else {
                effectiveCommand = request.getEffectiveCommand();
            }

            // 1. Parse the command
            ParsedCommand parsedCommand = commandParser.parse(effectiveCommand);
            
            // 2. Ensure tools are installed and get the binary path
            String toolPath = toolInstaller.ensureToolAvailable(
                    parsedCommand.getExecutable(),
                    request.getToolVersions() != null ? 
                            request.getToolVersions().get(parsedCommand.getExecutable()) : null
            );
            log.debug("Tool path resolved: {} -> {}", parsedCommand.getExecutable(), toolPath);
            
            // 3. Update the parsed command with the full binary path
            // CRITICAL: nsjail requires absolute paths inside the chroot
            parsedCommand.setExecutable(toolPath);

            // 4. Create and configure sandbox
            var sandboxFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return sandboxManager.executeInSandbox(request, parsedCommand, executionId);
                } catch (Exception e) {
                    throw new CompletionException(e);
                }
            }, executorService);

            // 5. Wait for completion with timeout
            int timeout = request.getTimeoutSecondsInt() + config.getExecution().getGracePeriodSeconds();
            try {
                ExecutionResult result = sandboxFuture.get(timeout, TimeUnit.SECONDS);
                result.setStartTime(startTime);
                result.setEndTime(Instant.now());
                result.setDurationMs(result.getEndTime().toEpochMilli() - startTime.toEpochMilli());
                return result;

            } catch (TimeoutException e) {
                log.warn("Execution {} timed out after {}s", executionId, timeout);
                sandboxFuture.cancel(true);
                sandboxManager.forceCleanup(executionId);
                
                return ExecutionResult.timeout(
                        executionId, "", "",
                        System.currentTimeMillis() - startTime.toEpochMilli());
            }

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            log.error("Execution {} failed: {}", executionId, cause.getMessage(), cause);
            String sanitizedMessage = sanitizeExceptionMessage(cause);
            return ExecutionResult.failure(
                    executionId, -1, "", sanitizedMessage,
                    System.currentTimeMillis() - startTime.toEpochMilli(),
                    sanitizedMessage);

        } catch (IOException e) {
            log.error("Execution {} failed to write script file: {}", executionId, e.getMessage(), e);
            return ExecutionResult.failure(
                    executionId, -1, "", "Failed to write script file: " + e.getMessage(),
                    System.currentTimeMillis() - startTime.toEpochMilli(),
                    "Failed to write script file: " + e.getMessage());

        } catch (Exception e) {
            log.error("Execution {} failed unexpectedly: {}", executionId, e.getMessage(), e);
            String sanitizedMessage = sanitizeExceptionMessage(e);
            return ExecutionResult.failure(
                    executionId, -1, "", sanitizedMessage,
                    System.currentTimeMillis() - startTime.toEpochMilli(),
                    sanitizedMessage);
        }
        // Note: Script file cleanup is handled by SandboxManager's workspace cleanup
    }

    /**
     * Get the file extension for a script language.
     */
    private String getScriptExtension(String language) {
        switch (language.toLowerCase()) {
            case "python":
                return ".py";
            case "bash":
            case "sh":
                return ".sh";
            default:
                return ".script";
        }
    }

    /**
     * Get the tool name for executing a script language.
     */
    private String getToolForLanguage(String language) {
        switch (language.toLowerCase()) {
            case "python":
                return "safe-python3";
            case "bash":
            case "sh":
                return "bash";
            default:
                throw new IllegalArgumentException("Unsupported script language: " + language);
        }
    }

    /**
     * Sanitize exception messages to prevent information leakage.
     * Removes sensitive information like file paths, system details, and internal errors.
     * 
     * @param e The exception to sanitize
     * @return A user-safe error message
     */
    private String sanitizeExceptionMessage(Throwable e) {
        if (e == null) {
            return "An unexpected error occurred";
        }
        
        String message = e.getMessage();
        if (message == null || message.isBlank()) {
            return "An unexpected error occurred: " + e.getClass().getSimpleName();
        }
        
        // Known safe exception types - pass through their messages
        // SecurityException messages are already user-friendly
        if (e instanceof SecurityException) {
            return message;
        }
        
        // IllegalArgumentException from our validators are also safe
        if (e instanceof IllegalArgumentException && isValidatorException(e)) {
            return message;
        }
        
        // For other exceptions, sanitize the message
        String sanitized = message;
        
        // Remove absolute file paths (Unix-style)
        sanitized = sanitized.replaceAll("/(?:var|opt|etc|home|root|tmp|usr|private)/[\\w/.-]+", "[path]");
        
        // Remove absolute file paths (common sandbox paths)
        sanitized = sanitized.replaceAll("/sandbox/[\\w/.-]+", "[path]");
        
        // Remove Java class paths and stack trace references
        sanitized = sanitized.replaceAll("at [a-zA-Z0-9$.]+\\([^)]+\\)", "");
        sanitized = sanitized.replaceAll("[a-zA-Z]+\\.[a-zA-Z]+\\.[a-zA-Z]+[a-zA-Z0-9$.]*", "[class]");
        
        // Remove IP addresses (but not port numbers alone)
        sanitized = sanitized.replaceAll("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", "[ip]");
        
        // Remove environment variable values that might contain secrets
        sanitized = sanitized.replaceAll("(?i)(password|secret|token|key|credential)s?[=:][^\\s,;]+", "$1=[redacted]");
        
        // Clean up any resulting double spaces or empty brackets
        sanitized = sanitized.replaceAll("\\s{2,}", " ").trim();
        
        // If sanitization removed too much content, return generic message
        if (sanitized.length() < 10 || sanitized.matches("^[\\s\\[\\].,:-]+$")) {
            return "Command execution failed. Check your command syntax and permissions.";
        }
        
        return sanitized;
    }
    
    /**
     * Check if an exception originated from our security validators.
     * These exceptions have user-friendly messages that are safe to display.
     */
    private boolean isValidatorException(Throwable e) {
        StackTraceElement[] stackTrace = e.getStackTrace();
        if (stackTrace == null || stackTrace.length == 0) {
            return false;
        }
        
        String className = stackTrace[0].getClassName();
        return className != null && (
                className.contains(".security.") ||
                className.contains(".validator.") ||
                className.contains("Validator") ||
                className.contains("Sanitizer")
        );
    }

    /**
     * Execute asynchronously with callback.
     */
    public CompletableFuture<ExecutionResult> executeAsync(SandboxRequest request, String executionId) {
        return CompletableFuture.supplyAsync(
                () -> execute(request, executionId),
                executorService
        );
    }

    /**
     * Mask sensitive parts of command for logging.
     */
    private String maskCommand(String command) {
        if (command == null) return "[null]";
        if (command.length() > 50) {
            return command.substring(0, 50) + "...";
        }
        return command;
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down execution orchestrator");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
