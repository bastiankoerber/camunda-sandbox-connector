package io.camunda.connector.sandbox.sandbox;

import io.camunda.connector.sandbox.config.SandboxConfig;
import io.camunda.connector.sandbox.model.ParsedCommand;
import io.camunda.connector.sandbox.model.SandboxRequest;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds nsjail configuration for sandbox execution.
 * 
 * This class provides two methods:
 * 1. buildCommand() - Builds nsjail command line arguments (List<String>)
 * 2. buildConfig() - Builds nsjail protobuf config file content (String)
 */
@Slf4j
public class NsjailConfigBuilder {

    private final SandboxConfig config;

    public NsjailConfigBuilder(SandboxConfig config) {
        this.config = config;
    }

    /**
     * Build the nsjail command line arguments.
     * 
     * IMPORTANT: nsjail boolean flags (--disable_clone_newpid, --disable_clone_newns, 
     * --keep_env, etc.) do NOT take arguments. They are toggles - their presence 
     * enables/disables a feature. Never add "true" or "false" after these flags,
     * as nsjail will interpret the next argument as the command to execute.
     *
     * @param request The sandbox request containing execution parameters
     * @param parsedCommand The parsed command to execute
     * @param workspacePath The path to the workspace directory
     * @return List of command line arguments for nsjail
     */
    public List<String> buildCommand(SandboxRequest request, ParsedCommand parsedCommand, Path workspacePath) {
        List<String> cmd = new ArrayList<>();
        cmd.add(config.getNsjailPath());

        // Basic mode
        cmd.add("--mode");
        cmd.add("o"); // Execute once

        // Time limit
        cmd.add("--time_limit");
        cmd.add(String.valueOf(request.getTimeoutSecondsInt()));

        // Resource limits
        cmd.add("--rlimit_as");
        cmd.add(String.valueOf(request.getMemoryLimitMbInt()));
        
        cmd.add("--rlimit_cpu");
        cmd.add(String.valueOf(request.getTimeoutSecondsInt() + 5));
        
        cmd.add("--rlimit_fsize");
        cmd.add("64"); // 64MB file size limit
        
        cmd.add("--rlimit_nofile");
        cmd.add("64"); // Max open files

        // User/Group mapping - only add if user namespace is enabled
        if (config.getSecurity().isUseUserNamespace()) {
            cmd.add("--user");
            cmd.add(String.valueOf(config.getSecurity().getSandboxUid()));
            cmd.add("--group");
            cmd.add(String.valueOf(config.getSecurity().getSandboxGid()));
        }

        // Namespaces - nsjail boolean flags do NOT take arguments!
        // By default nsjail enables all namespaces, so we only add disable flags when needed.
        // CRITICAL: Do NOT add "true" or "false" after these flags!
        if (!config.getSecurity().isUsePidNamespace()) {
            cmd.add("--disable_clone_newpid");
            // NO argument after this flag!
        }
        
        if (!config.getSecurity().isUseMountNamespace()) {
            cmd.add("--disable_clone_newns");
            // NO argument after this flag!
        }

        // Network namespace - disable network isolation if network access is requested
        boolean networkEnabled = request.getNetworkAccess() != null && 
                                 request.getNetworkAccess() != SandboxRequest.NetworkAccess.NONE;
        if (networkEnabled) {
            cmd.add("--disable_clone_newnet");
            // NO argument after this flag!
        }

        // Chroot / Filesystem
        cmd.add("--chroot");
        cmd.add(config.getSandboxRootfs());

        // Mount workspace
        cmd.add("--bindmount");
        cmd.add(workspacePath.toString() + ":/workspace");

        // Mount tools (read-only)
        cmd.add("--bindmount_ro");
        cmd.add(config.getToolsDirectory() + ":/tools");
        
        // Mount DNS configuration for network access (required for hostname resolution)
        if (networkEnabled) {
            cmd.add("--bindmount_ro");
            cmd.add("/etc/resolv.conf:/etc/resolv.conf");
        }

        // Working directory
        cmd.add("--cwd");
        cmd.add("/workspace");

        // Seccomp policy - disabled for now as nsjail requires kafel format, not JSON
        // TODO: Convert JSON seccomp policies to kafel format or create kafel policies
        // Path seccompPath = config.getSeccompProfilePath(config.getSecurity().getDefaultSeccompProfile());
        // if (Files.exists(seccompPath)) {
        //     cmd.add("--seccomp_policy");
        //     cmd.add(seccompPath.toString());
        // }

        // Environment variables - don't pass host environment
        // Note: --keep_env is a boolean flag, absence means don't keep host env
        // Pass only specific environment variables with --env KEY=VALUE
        if (request.getEnvironment() != null) {
            for (Map.Entry<String, String> entry : request.getEnvironment().entrySet()) {
                cmd.add("--env");
                cmd.add(entry.getKey() + "=" + entry.getValue());
            }
        }

        // Command separator - everything after this is the actual command to execute
        cmd.add("--");

        // The actual command to execute (executable + arguments)
        cmd.addAll(parsedCommand.toCommandList());

        return cmd;
    }

    /**
     * Build a nsjail configuration file content.
     */
    public String buildConfig(
            String executionId,
            List<String> command,
            Map<String, String> environment,
            int timeoutSeconds,
            int memoryMb,
            boolean networkEnabled,
            Path workspacePath) {
        
        StringBuilder sb = new StringBuilder();
        
        sb.append("# Auto-generated nsjail config for execution: ").append(executionId).append("\n");
        sb.append("name: \"sandbox-").append(executionId).append("\"\n");
        sb.append("\n");
        
        // Mode
        sb.append("mode: ONCE\n");
        sb.append("\n");
        
        // Hostname
        sb.append("hostname: \"sandbox\"\n");
        sb.append("\n");
        
        // Time limit
        sb.append("time_limit: ").append(timeoutSeconds).append("\n");
        sb.append("\n");
        
        // Resource limits
        sb.append("rlimit_as: ").append(memoryMb).append("\n");
        sb.append("rlimit_cpu: ").append(timeoutSeconds + 5).append("\n");
        sb.append("rlimit_fsize: 64\n");
        sb.append("rlimit_nofile: 64\n");
        sb.append("rlimit_nproc: 32\n");
        sb.append("\n");
        
        // Namespaces
        sb.append("clone_newnet: ").append(!networkEnabled).append("\n");
        sb.append("clone_newuser: true\n");
        sb.append("clone_newns: true\n");
        sb.append("clone_newpid: true\n");
        sb.append("clone_newipc: true\n");
        sb.append("clone_newuts: true\n");
        sb.append("\n");
        
        // User mapping
        sb.append("uidmap {\n");
        sb.append("  inside_id: \"").append(config.getSecurity().getSandboxUid()).append("\"\n");
        sb.append("  outside_id: \"").append(config.getSecurity().getSandboxUid()).append("\"\n");
        sb.append("  count: 1\n");
        sb.append("}\n");
        sb.append("\n");
        
        sb.append("gidmap {\n");
        sb.append("  inside_id: \"").append(config.getSecurity().getSandboxGid()).append("\"\n");
        sb.append("  outside_id: \"").append(config.getSecurity().getSandboxGid()).append("\"\n");
        sb.append("  count: 1\n");
        sb.append("}\n");
        sb.append("\n");
        
        // Mounts
        sb.append("mount {\n");
        sb.append("  src: \"").append(config.getSandboxRootfs()).append("\"\n");
        sb.append("  dst: \"/\"\n");
        sb.append("  is_bind: true\n");
        sb.append("  rw: false\n");
        sb.append("}\n");
        sb.append("\n");
        
        sb.append("mount {\n");
        sb.append("  src: \"").append(workspacePath.toString()).append("\"\n");
        sb.append("  dst: \"/workspace\"\n");
        sb.append("  is_bind: true\n");
        sb.append("  rw: true\n");
        sb.append("}\n");
        sb.append("\n");
        
        sb.append("mount {\n");
        sb.append("  src: \"").append(config.getToolsDirectory()).append("\"\n");
        sb.append("  dst: \"/tools\"\n");
        sb.append("  is_bind: true\n");
        sb.append("  rw: false\n");
        sb.append("}\n");
        sb.append("\n");
        
        // /dev mounts
        sb.append("mount {\n");
        sb.append("  dst: \"/dev\"\n");
        sb.append("  fstype: \"tmpfs\"\n");
        sb.append("  rw: true\n");
        sb.append("}\n");
        sb.append("\n");
        
        sb.append("mount {\n");
        sb.append("  src: \"/dev/null\"\n");
        sb.append("  dst: \"/dev/null\"\n");
        sb.append("  is_bind: true\n");
        sb.append("  rw: true\n");
        sb.append("}\n");
        sb.append("\n");
        
        sb.append("mount {\n");
        sb.append("  src: \"/dev/urandom\"\n");
        sb.append("  dst: \"/dev/urandom\"\n");
        sb.append("  is_bind: true\n");
        sb.append("  rw: false\n");
        sb.append("}\n");
        sb.append("\n");
        
        // /tmp
        sb.append("mount {\n");
        sb.append("  dst: \"/tmp\"\n");
        sb.append("  fstype: \"tmpfs\"\n");
        sb.append("  rw: true\n");
        sb.append("}\n");
        sb.append("\n");
        
        // /proc
        sb.append("mount {\n");
        sb.append("  dst: \"/proc\"\n");
        sb.append("  fstype: \"proc\"\n");
        sb.append("  rw: false\n");
        sb.append("}\n");
        sb.append("\n");
        
        // Working directory
        sb.append("cwd: \"/workspace\"\n");
        sb.append("\n");
        
        // Environment
        sb.append("keep_env: false\n");
        if (environment != null) {
            for (Map.Entry<String, String> entry : environment.entrySet()) {
                sb.append("envar: \"").append(entry.getKey()).append("=").append(entry.getValue()).append("\"\n");
            }
        }
        // Default env vars
        sb.append("envar: \"PATH=/tools:/usr/local/bin:/usr/bin:/bin\"\n");
        sb.append("envar: \"HOME=/workspace\"\n");
        sb.append("envar: \"USER=sandbox\"\n");
        sb.append("\n");
        
        // Seccomp
        Path seccompPath = config.getSeccompProfilePath(config.getSecurity().getDefaultSeccompProfile());
        sb.append("seccomp_policy_file: \"").append(seccompPath.toString()).append("\"\n");
        sb.append("\n");
        
        // Command
        for (String arg : command) {
            sb.append("exec_bin {\n");
            sb.append("  path: \"").append(arg).append("\"\n");
            sb.append("}\n");
        }
        
        return sb.toString();
    }
}
