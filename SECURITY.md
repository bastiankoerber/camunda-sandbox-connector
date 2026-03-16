# Sandbox CLI Connector - Security Architecture

## Executive Summary

The Sandbox CLI Connector provides **production-grade, SaaS-ready** command execution in a multi-tenant environment. It implements defense-in-depth security with **10+ layers of protection**, making it suitable for executing untrusted CLI commands from AI agents, workflow automation, and user-submitted tasks.

**Key Security Properties:**
- Complete process isolation via Linux namespaces
- Syscall filtering via seccomp-BPF (blocks 300+ dangerous syscalls)
- Resource limits via cgroups v2 (CPU, memory, processes)
- Network isolation with optional controlled egress
- Read-only filesystem with minimal attack surface
- Multi-tenant isolation with per-tenant policies
- Command injection prevention (Unicode, shell operators, encoded chars)
- Tool allowlisting with subcommand/flag restrictions

---

## Why This Is Safe for SaaS Deployment

### 1. Battle-Tested Foundation

| Component | Source | Track Record |
|-----------|--------|--------------|
| **nsjail** | Google | Used in Google's production systems, CTF competitions |
| **Linux Namespaces** | Linux Kernel | Core container technology (Docker, Kubernetes) |
| **Seccomp-BPF** | Linux Kernel | Used by Chrome, Firefox, systemd, Docker |
| **Cgroups v2** | Linux Kernel | Production resource management in all major clouds |

### 2. Defense in Depth

Even if one security layer is bypassed, multiple additional layers prevent exploitation:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1: Input Validation                                          │
│  ├── Command injection detection (shell operators, Unicode tricks)  │
│  ├── Path traversal prevention                                      │
│  └── Argument length limits                                         │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Tool Allowlisting                                         │
│  ├── Only pre-approved tools can execute                            │
│  ├── Subcommand restrictions (e.g., kubectl get OK, delete blocked) │
│  └── Flag restrictions (e.g., --dry-run OK, --force blocked)        │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Tenant Isolation                                          │
│  ├── Per-tenant tool permissions                                    │
│  ├── Per-tenant resource limits                                     │
│  └── Per-tenant network policies                                    │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Linux Namespaces (nsjail)                                 │
│  ├── PID namespace (can't see/signal host processes)                │
│  ├── Mount namespace (isolated filesystem view)                     │
│  ├── Network namespace (isolated network stack)                     │
│  ├── User namespace (no real root privileges)                       │
│  ├── IPC namespace (isolated shared memory)                         │
│  └── UTS namespace (isolated hostname)                              │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 5: Seccomp-BPF Syscall Filtering                             │
│  ├── Default: ~90 allowed syscalls (out of 400+)                    │
│  ├── Blocks: ptrace, mount, reboot, kernel modules, BPF             │
│  └── Restricts: clone (no new namespaces), ioctl (limited)          │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 6: Cgroups v2 Resource Limits                                │
│  ├── Memory: Hard limit with no swap                                │
│  ├── CPU: Time-based limits                                         │
│  └── PIDs: Process count limits                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 7: Filesystem Restrictions                                   │
│  ├── Read-only root filesystem                                      │
│  ├── Minimal /dev (null, zero, urandom only)                        │
│  ├── tmpfs /tmp with size limits                                    │
│  └── No access to host filesystem                                   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 8: Capability Dropping                                       │
│  ├── All capabilities dropped                                       │
│  ├── Runs as nobody (UID 65534)                                     │
│  └── No privilege escalation possible                               │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 9: Interpreter Security (Python, etc.)                       │
│  ├── Module import blocking (os, subprocess, socket, etc.)          │
│  ├── Inline code only (-c flag)                                     │
│  └── No package installation                                        │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 10: Output Sanitization                                      │
│  ├── Output size limits                                             │
│  ├── Timeout enforcement                                            │
│  └── Error message sanitization                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Threat Model & Mitigations

### Attack Category 1: Command Injection

**Threat:** Attacker crafts input to execute arbitrary commands.

| Attack Vector | Example | Mitigation |
|---------------|---------|------------|
| Shell operators | `curl http://x; rm -rf /` | Blocked: `;`, `&&`, `\|\|`, `\|` |
| Command substitution | `curl $(cat /etc/passwd)` | Blocked: `$()`, backticks |
| Redirections | `cat /etc/passwd > /tmp/leak` | Blocked: `>`, `>>`, `<` |
| Variable expansion | `curl $HOME/.ssh/id_rsa` | Blocked: `${var}`, `$VAR` |
| Backgrounding | `curl http://x & malware` | Blocked: trailing `&` |
| Unicode tricks | `curl；rm -rf /` (fullwidth ;) | Blocked: Unicode homoglyphs |
| Encoded chars | `curl%20%26%26%20rm` | Blocked: URL/hex encoding |
| Null bytes | `curl\x00--help` | Blocked: null byte injection |

**Code:** `InjectionDetector.java` - 50+ regex patterns

### Attack Category 2: Container/Sandbox Escape

**Threat:** Attacker breaks out of sandbox to access host system.

| Attack Vector | Mitigation |
|---------------|------------|
| **Namespace escape via `nsenter`** | Blocked executable; blocked syscalls `setns`, `unshare` |
| **Mount manipulation** | Blocked syscalls: `mount`, `umount2`, `pivot_root` |
| **Ptrace injection** | Blocked syscall: `ptrace` |
| **Kernel module loading** | Blocked syscalls: `init_module`, `finit_module`, `delete_module` |
| **BPF exploitation** | Blocked syscall: `bpf` |
| **Docker socket access** | Path blocked: `/var/run/docker.sock`, `/run/containerd/` |
| **Proc filesystem escape** | `/proc` mounted read-only; sensitive paths blocked |
| **Device access** | Minimal `/dev` (only null, zero, urandom, random) |
| **Capability abuse** | All capabilities dropped (`keep_caps: false`) |
| **User namespace tricks** | Runs as `nobody` (65534); no capability to create new namespaces |

**Code:** `seccomp/default.json` - Explicit syscall blocklist

### Attack Category 3: Resource Exhaustion (DoS)

**Threat:** Attacker consumes resources to impact other tenants or host.

| Attack Vector | Mitigation |
|---------------|------------|
| **Memory exhaustion** | Cgroups limit: 512MB max, 0 swap |
| **CPU exhaustion** | Cgroups limit: 500ms/s (50% of 1 core); rlimit: 60s CPU time |
| **Fork bomb** | Cgroups PID limit: 64 processes; rlimit_nproc: 64 |
| **Disk exhaustion** | tmpfs /tmp: 64MB; rlimit_fsize: 64MB |
| **File descriptor exhaustion** | rlimit_nofile: 256 |
| **Infinite loop** | Time limit: 300s (5 min) hard kill |
| **Output flooding** | maxOutputBytes: 1MB per execution |

**Code:** `nsjail/default.cfg` - Resource limits

### Attack Category 4: Data Exfiltration

**Threat:** Attacker steals sensitive data from host or other tenants.

| Attack Vector | Mitigation |
|---------------|------------|
| **Read host files** | Chroot to minimal rootfs; no host filesystem access |
| **Read /etc/shadow** | Path blocked; not in rootfs |
| **Read cloud metadata** | Blocked hosts: `169.254.169.254`, `metadata.google.internal` |
| **Environment variable leaks** | Dangerous env vars blocked (LD_*, PATH, HOME, etc.) |
| **Core dump secrets** | rlimit_core: 0 (no core dumps) |
| **Cross-tenant access** | Separate namespaces per execution; no shared state |
| **Network exfiltration** | Network disabled by default; allowlist when enabled |

**Code:** `SecurityValidator.java`, `TenantPolicy.NetworkPolicy`

### Attack Category 5: Privilege Escalation

**Threat:** Attacker gains elevated privileges.

| Attack Vector | Mitigation |
|---------------|------------|
| **Setuid binaries** | No setuid binaries in rootfs |
| **Sudo/su** | Blocked executables |
| **Capability manipulation** | Blocked syscalls: `capset`; tools blocked: `setcap`, `capsh` |
| **Library injection (LD_PRELOAD)** | All `LD_*` environment variables blocked |
| **macOS dyld injection** | All `DYLD_*` environment variables blocked |
| **Python path injection** | `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME` blocked |
| **Node.js injection** | `NODE_PATH`, `NODE_OPTIONS` blocked |
| **Java injection** | `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` blocked |

**Code:** `SecurityValidator.java` - Environment variable blocklist

### Attack Category 6: Network Attacks

**Threat:** Attacker uses sandbox for network attacks or C2 communication.

| Attack Vector | Mitigation |
|---------------|------------|
| **Outbound connections** | Network namespace isolation (disabled by default) |
| **Port scanning** | Network disabled; when enabled, host allowlist |
| **Reverse shells** | Blocked: `nc`, `netcat`; network syscalls filtered |
| **DNS tunneling** | DNS only when network explicitly allowed |
| **SSRF to internal services** | Blocked hosts: metadata endpoints, internal ranges |
| **Proxy abuse** | Blocked env vars: `HTTP_PROXY`, `HTTPS_PROXY`, etc. |

**Code:** `NsjailConfigBuilder.java`, `TenantPolicy.NetworkPolicy`

### Attack Category 7: Interpreter Abuse (Python, Node.js)

**Threat:** Attacker uses scripting interpreter to bypass restrictions.

| Attack Vector | Mitigation |
|---------------|------------|
| **os.system()** | Blocked: `import os` pattern |
| **subprocess.run()** | Blocked: `import subprocess` pattern |
| **socket connections** | Blocked: `import socket` pattern |
| **eval/exec** | Blocked: `eval(`, `exec(` patterns |
| **pickle deserialization** | Blocked: `import pickle` pattern |
| **Dynamic imports** | Blocked: `__import__`, `importlib` patterns |
| **File operations** | Blocked: `import shutil`, `import tempfile` |
| **Running scripts** | Only `-c` inline code allowed; no file execution |
| **Installing packages** | Blocked: `pip install` pattern; read-only filesystem |

**Code:** `docker/wrappers/safe-python3` - 40+ blocked patterns

### Attack Category 8: Supply Chain Attacks

**Threat:** Attacker compromises tool binaries.

| Attack Vector | Mitigation |
|---------------|------------|
| **Malicious tool binary** | SHA256 checksum verification required |
| **Man-in-the-middle download** | HTTPS-only download URLs |
| **Compromised package registry** | Tools installed at build time, not runtime |
| **Dependency confusion** | Fixed versions in registry.yaml |

**Code:** `tools/registry.yaml` - Checksum verification

---

## Security Configuration Reference

### Seccomp Profiles

| Profile | Use Case | Allowed Syscalls | Blocked |
|---------|----------|------------------|---------|
| `default` | Read-only tools (jq, grep) | ~90 | ptrace, mount, bpf, modules |
| `network` | Network tools (curl, http) | ~130 | + socket, connect, etc. |
| `permissive` | Cloud CLIs (aws, gcloud) | ~180 | + file modifications |

### Resource Limits

| Resource | Default | Maximum | Notes |
|----------|---------|---------|-------|
| Memory | 256 MB | 4 GB | No swap allowed |
| CPU Time | 60s | 900s | Hard kill at limit |
| Timeout | 30s | 900s | Wall-clock time |
| Processes | 64 | 64 | Fork bomb protection |
| Open Files | 256 | 256 | FD exhaustion protection |
| File Size | 64 MB | 64 MB | Disk exhaustion protection |
| Output | 1 MB | 1 MB | Log flooding protection |

### Network Policies

| Mode | Description | Use Case |
|------|-------------|----------|
| `NONE` | No network access | Data processing (jq, awk) |
| `INTERNAL` | Internal services only | Service-to-service calls |
| `RESTRICTED` | Allowlisted hosts only | Specific API calls |
| `FULL` | Full network (discouraged) | Development only |

---

## Compliance Considerations

### SOC 2 Type II

| Control | Implementation |
|---------|----------------|
| **Access Control** | Tenant isolation, tool allowlisting |
| **System Operations** | Audit logging, resource monitoring |
| **Risk Mitigation** | Defense in depth, input validation |
| **Change Management** | Immutable container images |

### GDPR / Data Protection

| Requirement | Implementation |
|-------------|----------------|
| **Data Isolation** | Separate namespaces per execution |
| **Access Logging** | Full audit trail |
| **Data Minimization** | Minimal rootfs, no persistent storage |

### PCI-DSS

| Requirement | Implementation |
|-------------|----------------|
| **Network Segmentation** | Network namespace isolation |
| **Access Control** | Tool and command allowlisting |
| **Audit Logging** | Execution audit trail |

---

## Comparison with Alternatives

| Feature | This Sandbox | Docker (default) | AWS Lambda | Firecracker |
|---------|--------------|------------------|------------|-------------|
| Syscall filtering | Yes (seccomp) | Optional | Yes | Yes |
| User namespaces | Yes | Optional | N/A | Yes |
| Memory limits | Yes (cgroups) | Yes | Yes | Yes |
| Network isolation | Yes | Partial | Yes | Yes |
| Command injection prevention | Yes | No | No | No |
| Tool allowlisting | Yes | No | N/A | No |
| Tenant policies | Yes | No | IAM | No |
| Interpreter restrictions | Yes | No | No | No |
| Attack surface | Minimal | Large | Medium | Minimal |

---

## Security Testing

### Automated Tests

```bash
# Run security test suite
mvn test -Dtest=*Security*

# Test injection detection
mvn test -Dtest=InjectionDetectorTest

# Test command parsing
mvn test -Dtest=CommandParserTest
```

### Manual Penetration Testing Checklist

- [ ] Command injection (all shell operators)
- [ ] Unicode homoglyph bypass
- [ ] Path traversal attacks
- [ ] Container escape attempts
- [ ] Resource exhaustion
- [ ] Network policy bypass
- [ ] Environment variable injection
- [ ] Interpreter escape (Python, Node)

---

## Incident Response

### If a Sandbox Escape is Suspected

1. **Isolate**: Stop the affected container immediately
2. **Preserve**: Capture container logs and state
3. **Analyze**: Review audit logs for the execution
4. **Patch**: Update seccomp/nsjail configuration
5. **Notify**: Follow security disclosure process

### Audit Log Location

```
/var/log/sandbox-connector/audit.log
```

### Key Log Fields

| Field | Description |
|-------|-------------|
| `executionId` | Unique execution identifier |
| `tenantId` | Tenant that initiated the request |
| `command` | Executed command (masked secrets) |
| `exitCode` | Process exit code |
| `duration` | Execution time |
| `securityViolation` | Any security violations detected |

---

## Version History

| Version | Date | Security Changes |
|---------|------|------------------|
| 1.0.0 | 2024-XX | Initial release with full security stack |

---

## References

- [nsjail Documentation](https://github.com/google/nsjail)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Seccomp-BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

---

## Contact

For security issues, please contact: [security@your-domain.com]

**Do not disclose security vulnerabilities publicly until a fix is available.**
