package io.camunda.connector.sandbox.integration;

import io.camunda.connector.sandbox.model.SandboxRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base class for sandbox integration tests.
 * Provides shared utilities for creating test requests and executing commands.
 */
public abstract class BaseSandboxIntegrationTest {

    protected static final Logger log = LoggerFactory.getLogger(BaseSandboxIntegrationTest.class);

    // Standard nsjail options for testing
    protected static final String NSJAIL_PATH = "/usr/bin/nsjail";
    protected static final String SANDBOX_ROOTFS = "/sandbox/rootfs";
    protected static final int SANDBOX_UID = 65534;
    protected static final int SANDBOX_GID = 65534;

    /**
     * Create a basic SandboxRequest for testing.
     */
    protected static SandboxRequest createTestRequest(String command, String... tools) {
        return SandboxRequest.builder()
            .command(command)
            .allowedTools(List.of(tools))
            .timeoutSeconds("30")
            .memoryLimitMb("256")
            .networkAccess(SandboxRequest.NetworkAccess.NONE)
            .build();
    }

    /**
     * Create a SandboxRequest with network access.
     */
    protected static SandboxRequest createNetworkRequest(String command, String... tools) {
        return SandboxRequest.builder()
            .command(command)
            .allowedTools(List.of(tools))
            .timeoutSeconds("30")
            .memoryLimitMb("256")
            .networkAccess(SandboxRequest.NetworkAccess.FULL)
            .build();
    }

    /**
     * Create a SandboxRequest with environment variables.
     */
    protected static SandboxRequest createRequestWithEnv(String command, Map<String, String> env, String... tools) {
        return SandboxRequest.builder()
            .command(command)
            .allowedTools(List.of(tools))
            .timeoutSeconds("30")
            .memoryLimitMb("256")
            .environment(env)
            .networkAccess(SandboxRequest.NetworkAccess.NONE)
            .build();
    }

    /**
     * Build nsjail command arguments for executing a command in the sandbox.
     * 
     * @param binaryPath The absolute path to the binary (e.g., /bin/curl)
     * @param args       Arguments to pass to the binary
     * @param networkEnabled Whether to enable network access
     * @param timeoutSeconds Timeout in seconds
     * @return List of command arguments to pass to container.execInContainer()
     */
    protected static List<String> buildNsjailCommand(
            String binaryPath,
            List<String> args,
            boolean networkEnabled,
            int timeoutSeconds) {
        
        List<String> cmd = new ArrayList<>();
        cmd.add(NSJAIL_PATH);
        cmd.add("--mode");
        cmd.add("o");
        cmd.add("--time_limit");
        cmd.add(String.valueOf(timeoutSeconds));
        cmd.add("--chroot");
        cmd.add(SANDBOX_ROOTFS);
        cmd.add("--cwd");
        cmd.add("/tmp");
        cmd.add("--user");
        cmd.add(String.valueOf(SANDBOX_UID));
        cmd.add("--group");
        cmd.add(String.valueOf(SANDBOX_GID));
        
        if (networkEnabled) {
            cmd.add("--disable_clone_newnet");
            // Mount DNS configuration for hostname resolution
            cmd.add("--bindmount_ro");
            cmd.add("/etc/resolv.conf:/etc/resolv.conf");
        }
        
        cmd.add("--");
        cmd.add(binaryPath);
        cmd.addAll(args);
        
        return cmd;
    }

    /**
     * Execute a command in the sandbox container and return the result.
     */
    protected static ExecResult execInSandbox(
            GenericContainer<?> container,
            String binaryPath,
            List<String> args,
            boolean networkEnabled,
            int timeoutSeconds) throws IOException, InterruptedException {
        
        List<String> cmd = buildNsjailCommand(binaryPath, args, networkEnabled, timeoutSeconds);
        log.debug("Executing: {}", String.join(" ", cmd));
        
        return container.execInContainer(cmd.toArray(new String[0]));
    }

    /**
     * Execute a simple command without network access.
     */
    protected static ExecResult execSimple(
            GenericContainer<?> container,
            String binaryPath,
            String... args) throws IOException, InterruptedException {
        
        return execInSandbox(container, binaryPath, List.of(args), false, 30);
    }

    /**
     * Execute a network command with DNS resolution.
     */
    protected static ExecResult execWithNetwork(
            GenericContainer<?> container,
            String binaryPath,
            String... args) throws IOException, InterruptedException {
        
        return execInSandbox(container, binaryPath, List.of(args), true, 30);
    }

    /**
     * Assert that an execution succeeded (exit code 0).
     */
    protected static void assertSuccess(ExecResult result, String description) {
        assertThat(result.getExitCode())
            .withFailMessage(
                "%s failed with exit code %d.\nStdout: %s\nStderr: %s",
                description, result.getExitCode(), result.getStdout(), result.getStderr())
            .isEqualTo(0);
    }

    /**
     * Assert that an execution failed (non-zero exit code).
     */
    protected static void assertFailure(ExecResult result, String description) {
        assertThat(result.getExitCode())
            .withFailMessage(
                "%s should have failed but succeeded.\nStdout: %s\nStderr: %s",
                description, result.getStdout(), result.getStderr())
            .isNotEqualTo(0);
    }

    /**
     * Assert that stdout contains expected text.
     */
    protected static void assertStdoutContains(ExecResult result, String expected) {
        assertThat(result.getStdout())
            .withFailMessage(
                "Expected stdout to contain '%s' but got:\n%s",
                expected, result.getStdout())
            .contains(expected);
    }

    /**
     * Assert that stdout equals expected text (trimmed).
     */
    protected static void assertStdoutEquals(ExecResult result, String expected) {
        assertThat(result.getStdout().trim())
            .withFailMessage(
                "Expected stdout to equal '%s' but got:\n%s",
                expected, result.getStdout())
            .isEqualTo(expected);
    }

    /**
     * Log execution result for debugging.
     */
    protected static void logResult(String description, ExecResult result) {
        log.info("{} - Exit code: {}", description, result.getExitCode());
        if (!result.getStdout().isBlank()) {
            log.info("{} - Stdout: {}", description, result.getStdout().trim());
        }
        if (!result.getStderr().isBlank()) {
            log.info("{} - Stderr: {}", description, result.getStderr().trim());
        }
    }

    /**
     * Interpret curl exit codes for better error messages.
     */
    protected static String interpretCurlExitCode(int exitCode) {
        return switch (exitCode) {
            case 0 -> "Success";
            case 1 -> "Unsupported protocol";
            case 2 -> "Failed to initialize";
            case 3 -> "URL malformed";
            case 5 -> "Could not resolve proxy";
            case 6 -> "Could not resolve host (DNS failure - check /etc/resolv.conf mount)";
            case 7 -> "Failed to connect to host";
            case 22 -> "HTTP error (4xx/5xx)";
            case 28 -> "Operation timeout";
            case 35 -> "SSL connect error";
            case 51 -> "SSL peer certificate error";
            case 52 -> "Empty reply from server";
            case 56 -> "Failure receiving network data";
            case 60 -> "SSL certificate problem";
            default -> "Unknown error (code " + exitCode + ")";
        };
    }

    /**
     * Interpret nsjail exit codes for better error messages.
     */
    protected static String interpretNsjailExitCode(int exitCode) {
        return switch (exitCode) {
            case 0 -> "Success";
            case 1 -> "Generic error";
            case 111 -> "Configuration error";
            case 137 -> "Killed by SIGKILL (likely OOM or force kill)";
            case 143 -> "Killed by SIGTERM (timeout or graceful shutdown)";
            case 255 -> "nsjail internal error (check process path, chroot, etc.)";
            default -> "Process exited with code " + exitCode;
        };
    }
}
