# Camunda Sandbox CLI Connector

A secure connector for executing CLI commands in a sandboxed environment for Camunda 8.9+.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Execution Modes](#execution-modes)
- [Element Template Properties](#element-template-properties)
- [Tenant Profiles](#tenant-profiles)
- [Tool Reference](#tool-reference)
- [Security Model](#security-model)
- [Output Structure](#output-structure)
- [Examples](#examples)
- [Common Workflows](#common-workflows)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Features

- **Secure Sandboxing**: Uses nsjail (Google's battle-tested sandbox) for process isolation
- **Two Execution Modes**: Command mode for CLI tools, Script mode for Python scripts
- **Multi-Tenant Support**: Per-tenant security policies and resource limits
- **Tool Allowlisting**: Only pre-approved CLI tools can be executed
- **Resource Limits**: CPU, memory, timeout constraints per execution
- **Command Injection Prevention**: Blocks shell operators, validates arguments
- **Network Isolation**: Configurable network access (none, internal, restricted, full)
- **Seccomp Profiles**: System call filtering for additional security

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Camunda Platform 8.9+                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Modeler   │    │    Zeebe    │    │    Operate/Tasklist │  │
│  │  (BPMN +    │───▶│   Gateway   │◀───│                     │  │
│  │  Template)  │    │             │    │                     │  │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘  │
└────────────────────────────┼────────────────────────────────────┘
                             │ Job
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Sandbox CLI Connector                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   Security   │  │    Tenant    │  │    Execution Engine    │ │
│  │  Validator   │──│    Policy    │──│                        │ │
│  │              │  │   Manager    │  │  ┌──────────────────┐  │ │
│  │ • Tool check │  │              │  │  │   Command Mode   │  │ │
│  │ • Arg block  │  │ • Allowlist  │  │  │   (jq, curl...)  │  │ │
│  │ • Injection  │  │ • Limits     │  │  ├──────────────────┤  │ │
│  └──────────────┘  │ • Network    │  │  │   Script Mode    │  │ │
│                    └──────────────┘  │  │   (Python)       │  │ │
│                                      │  └────────┬─────────┘  │ │
│                                      └───────────┼────────────┘ │
└──────────────────────────────────────────────────┼──────────────┘
                                                   │
                                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                          nsjail Sandbox                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  • PID namespace isolation    • Read-only root filesystem   ││
│  │  • Network namespace          • Seccomp syscall filtering   ││
│  │  • User namespace (non-root)  • cgroups resource limits     ││
│  │  • Mount namespace            • No capability escalation    ││
│  └─────────────────────────────────────────────────────────────┘│
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │     CLI Tool (jq, curl, aws, kubectl, safe-python3...)   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Flow:**
1. User designs workflow in Camunda Modeler using element templates
2. Workflow deployed to Zeebe, jobs dispatched to connector
3. Connector validates request against tenant security policy
4. Command/script executed inside nsjail sandbox
5. Result returned to workflow (stdout, stderr, exit code)

## Quick Start

### Option 1: Run with Docker Compose (Recommended)

```bash
cd /path/to/sandbox_connector
docker compose -f docker/docker-compose.yaml up -d
```

### Option 2: Run with Docker

```bash
# Build the Docker image
docker build -f docker/Dockerfile -t sandbox-connector:latest .

# Run the connector (requires privileged mode for nsjail)
docker run -d \
  --name sandbox-connector \
  --privileged \
  -p 8080:8080 \
  -e ZEEBE_CLIENT_BROKER_GATEWAY-ADDRESS=localhost:26500 \
  -e ZEEBE_CLIENT_SECURITY_PLAINTEXT=true \
  sandbox-connector:latest
```

### Option 3: Deploy to Kubernetes

```bash
helm install sandbox-connector ./charts/sandbox-connector \
  --namespace camunda \
  --set config.sandbox.enabled=true \
  --set image.repository=your-registry/sandbox-connector \
  --set image.tag=1.0.0
```

**Important**: Kubernetes deployment requires:
- `privileged: true` or specific capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE)
- `kernel.unprivileged_userns_clone=1` sysctl setting

### Installing the Element Template

**Option A: Combined Template (All Tenants)**

Use `element-templates/sandbox-cli-connector.json` for a single template that supports all tenants:

1. Copy `element-templates/sandbox-cli-connector.json` to your Camunda Modeler templates folder:
   - **macOS**: `~/Library/Application Support/camunda-modeler/resources/element-templates/`
   - **Windows**: `%APPDATA%/camunda-modeler/resources/element-templates/`
   - **Linux**: `~/.config/camunda-modeler/resources/element-templates/`

2. Restart Camunda Modeler

3. In your BPMN diagram, add a Service Task and select "Sandbox CLI Connector" from the template catalog

**Option B: Tenant-Specific Templates (Recommended for Teams)**

For teams that only need access to specific security profiles, use the per-tenant templates:

```
element-templates/
├── sandbox-cli-connector.json              # All tenants
├── sandbox-cli-connector-default.json      # Data processing only
├── sandbox-cli-connector-development.json  # Development tools
├── sandbox-cli-connector-cloud-ops.json    # Cloud CLIs
├── sandbox-cli-connector-infra-automation.json  # Terraform
└── sandbox-cli-connector-monitoring.json   # Read-only monitoring
```

Copy only the templates your team needs. This provides a cleaner UI with fewer options.

**Regenerating Templates**

When you modify `connector-core/src/main/resources/tenant/policies.yaml`, regenerate the templates:

```bash
python3 scripts/generate-element-templates.py
```

This ensures element templates always match your security policies.

## Execution Modes

The connector supports two execution modes:

### Command Mode

Execute CLI tools with arguments. Best for single-purpose operations like parsing JSON, making HTTP requests, or querying cloud resources.

**How it works:**
1. Select a CLI tool from the tenant-specific dropdown
2. Provide arguments (the tool name is added automatically)
3. Optionally provide stdin data
4. Command is validated and executed in sandbox

**Security restrictions:**
- Shell operators (`|`, `&`, `;`, `>`, `<`, `$()`, backticks) are **blocked**
- Arguments are validated against tenant blocklist
- Only allowlisted tools can be used

**Example - Parse JSON with jq:**
```
Execution Mode: Command
Tool: jq
Arguments: '.users[] | select(.active) | .name'
Input Data: =processVariableWithJson
```

### Script Mode

Execute multi-line Python scripts. Best for complex data transformations, calculations, or operations requiring multiple steps.

**How it works:**
1. Select `safe-python3` as the tool
2. Write your Python script in the Script Content field
3. Script is written to a temporary file and executed via `safe-python3`
4. Output (stdout) is captured and returned

**Available Python modules:**
```
json, math, statistics, hashlib, base64, datetime, 
collections, itertools, functools, re, string, textwrap,
decimal, fractions, random, uuid, urllib.parse
```

**Security restrictions:**
- No filesystem access (except reading stdin)
- No network access (unless tenant allows)
- No subprocess/os.system calls
- No import of dangerous modules (os, sys, subprocess, etc.)

**Example - Complex data transformation:**
```
Execution Mode: Script
Tool: safe-python3
Script Language: python
Script Content:
import json
import statistics

data = json.loads(input())
values = [item['value'] for item in data['items']]

result = {
    'count': len(values),
    'sum': sum(values),
    'mean': statistics.mean(values),
    'median': statistics.median(values)
}

print(json.dumps(result))
```

**Passing data to scripts:**
- Use `input()` to read stdin (from Input Data field)
- Parse JSON input with `json.loads(input())`
- Print output as JSON with `print(json.dumps(result))`

### Choosing Between Modes

| Use Case | Mode | Why |
|----------|------|-----|
| Parse/transform JSON | Command (jq) | jq is faster and more memory efficient |
| Make HTTP request | Command (curl) | Native tool, handles edge cases |
| Complex calculations | Script (Python) | Python has math/statistics libraries |
| Multi-step transformation | Script (Python) | Logic is clearer in Python |
| String manipulation | Either | jq for JSON paths, Python for regex |
| Data aggregation | Script (Python) | Python collections/itertools |

## Element Template Properties

### Tenant & Tool Selection

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| **Tenant Profile** | Dropdown | Yes | Security profile defining available tools, resource limits, and network policies. Each profile is a preset - ensure you have appropriate permissions to use the selected profile. |
| **CLI Tool** | Dropdown | Yes | The CLI tool to execute. Options change based on the selected tenant profile. |

### Command Configuration

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| **Arguments** | Text | Yes | Command arguments (without the tool name). Example for curl: `-s https://api.example.com/data`. Shell operators (`\|`, `&`, `;`, `>`) are blocked for security. |
| **Input Data (stdin)** | Text | No | JSON/YAML data passed to the command's stdin. Perfect for processing with jq/yq. Use a process variable (e.g., `=myJsonData`) or a literal value. |
| **Environment Variables** | Text | No | Additional environment variables as JSON object. Example: `{"API_KEY": "{{secrets.MY_KEY}}"}`. Variables are isolated to this execution. |

### Security & Limits

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| **Timeout** | Dropdown | 30s | Maximum execution time. Process is terminated if exceeded. Choose 10s for simple queries, 60-120s for cloud operations, 300s for complex tasks. |
| **Memory Limit** | Dropdown | 256MB | Maximum RAM. Process is killed (OOM) if exceeded. 128MB for text processing, 512MB for cloud CLIs, 1024MB for Terraform. |
| **Network Access** | Dropdown | NONE | Network isolation level. NONE=no network (most secure), INTERNAL=cluster only, RESTRICTED=allowlisted hosts, FULL=any destination. |

### Output Mapping

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| **Result Variable** | String | sandboxResult | Process variable name for the result object containing stdout, stderr, exitCode, success, executionTimeMs, and resourceUsage. |
| **Result Expression** | FEEL | - | Transform the result before storing. Example: `={output: response.stdout, success: response.exitCode = 0}` |

### Error Handling

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| **Error Expression** | FEEL | - | FEEL expression evaluated on errors. Access: error.code, error.message. |
| **Retries** | Dropdown | 3 | Retry count for transient failures. Uses exponential backoff. Set to 0 for no retries. |

## Tenant Profiles

### What are Tenants?

Tenants (also called "Security Profiles") are **pre-configured security policies** that define:

1. **Which tools can be used** - Each tenant has an allowlist of CLI tools
2. **What operations are blocked** - Dangerous arguments (like `delete`, `--upload-file`) can be blocked per tool
3. **Resource limits** - CPU, memory, timeout, and concurrency limits
4. **Network access** - Which external hosts can be reached
5. **Secrets** - Which credentials are available to the tools

**Why use tenants?**

- **Principle of Least Privilege**: Users only get access to tools they need
- **Blast Radius Reduction**: If a process is compromised, damage is limited to what the tenant allows
- **Compliance**: Different teams/environments can have different security postures
- **Resource Isolation**: Prevent one workflow from consuming all resources

**How it works in the Element Template:**

When you select a tenant/security profile in the Camunda Modeler, the tool dropdown automatically shows only the tools allowed for that tenant. This prevents users from accidentally selecting tools they don't have permission to use.

### Available Element Templates

We provide two types of element templates:

| Template | File | Use Case |
|----------|------|----------|
| **Combined** | `sandbox-cli-connector.json` | Shows all tenants in a dropdown. Tool list changes based on selection. |
| **Tenant-specific** | `sandbox-cli-connector-{tenant}.json` | Pre-configured for one tenant. Simpler UI, only shows allowed tools. |

**Generate templates from policies:**

When you modify `policies.yaml`, regenerate the element templates:

```bash
python3 scripts/generate-element-templates.py
```

This ensures the element templates always match your security policies.

### Tenant Overview

Each tenant profile is a security preset that defines allowed tools, resource limits, and network policies.

### Default Profile

**Use case**: Local data processing without network access.

| Setting | Value |
|---------|-------|
| **Tools** | jq, yq, grep, sed, awk |
| **Network** | Disabled |
| **CPU** | 500 millicores |
| **Memory** | 128 MB |
| **Timeout** | 30 seconds |

**Example**:
```
Tool: jq
Arguments: '.users[] | select(.active == true) | .email'
Input Data: =processVariable
Network Access: NONE
```

### Development Profile

**Use case**: Development and testing with controlled external access.

| Setting | Value |
|---------|-------|
| **Tools** | curl, jq, yq, git (read-only), kubectl (read-only), helm (read-only) |
| **Network** | Restricted (GitHub, NPM, Kubernetes API) |
| **CPU** | 1000 millicores |
| **Memory** | 512 MB |
| **Timeout** | 120 seconds |

**Blocked operations**:
- git: push, clone, fetch, pull
- kubectl: exec, delete, apply, create
- helm: install, upgrade, uninstall
- curl: --upload-file, -T

**Example**:
```
Tool: curl
Arguments: -s https://api.github.com/repos/camunda/camunda/releases/latest
Network Access: RESTRICTED
```

### Cloud Operations Profile

**Use case**: Cloud infrastructure management with major providers.

| Setting | Value |
|---------|-------|
| **Tools** | aws, gcloud, az, kubectl, curl, jq |
| **Network** | AWS, GCP, Azure endpoints |
| **CPU** | 2000 millicores |
| **Memory** | 1024 MB |
| **Timeout** | 300 seconds |

**Blocked operations**:
- aws: iam delete, ec2 terminate, s3 rb, rds delete
- gcloud: compute instances delete, iam service-accounts delete, projects delete
- az: vm delete, group delete, keyvault delete

**Required credentials**: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GOOGLE_APPLICATION_CREDENTIALS (configured in connector environment)

**Example**:
```
Tool: aws
Arguments: s3 ls s3://my-bucket --recursive
Network Access: RESTRICTED
Memory: 512 MB
```

### Infrastructure Automation Profile

**Use case**: Infrastructure as Code workflows with Terraform.

| Setting | Value |
|---------|-------|
| **Tools** | terraform, jq, yq |
| **Network** | Terraform Registry, cloud providers |
| **CPU** | 4000 millicores |
| **Memory** | 2048 MB |
| **Timeout** | 600 seconds |

**Blocked operations**:
- terraform: apply -auto-approve, destroy, import, taint, force-unlock

**Example**:
```
Tool: terraform
Arguments: plan -out=plan.tfplan
Network Access: RESTRICTED
Timeout: 300 seconds
Memory: 1024 MB
```

### Monitoring Profile

**Use case**: Read-only observability and health checks.

| Setting | Value |
|---------|-------|
| **Tools** | kubectl (read-only), curl (GET only), jq |
| **Network** | Kubernetes API, Prometheus, Grafana |
| **CPU** | 500 millicores |
| **Memory** | 256 MB |
| **Timeout** | 60 seconds |

**Blocked operations**:
- kubectl: exec, delete, apply, create, patch, replace, edit
- curl: POST, PUT, DELETE, PATCH, --data, --upload-file

**Example**:
```
Tool: kubectl
Arguments: get pods -n production -o json
Network Access: INTERNAL
```

## Tool Reference

Quick reference for all available CLI tools across tenants.

### Data Processing Tools

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **jq** | JSON processor | `jq '.users[].name'` | all |
| **yq** | YAML/JSON/XML processor | `yq -o=json '.spec'` | default, development, infra |
| **grep** | Pattern matching | `grep -E 'error\|warning'` | default |
| **sed** | Stream editor | `sed 's/old/new/g'` | default |
| **awk** | Text processing | `awk '{print $1}'` | default |

### Network Tools

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **curl** | HTTP client | `curl -s https://api.example.com` | development, cloud-ops, monitoring |

### Cloud CLIs

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **aws** | AWS CLI | `aws s3 ls` | cloud-ops |
| **gcloud** | Google Cloud CLI | `gcloud compute instances list` | cloud-ops |
| **az** | Azure CLI | `az vm list` | cloud-ops |

### Kubernetes Tools

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **kubectl** | Kubernetes CLI | `kubectl get pods -o json` | development, cloud-ops, monitoring |
| **helm** | Kubernetes package manager | `helm list -A` | development |

### Infrastructure Tools

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **terraform** | Infrastructure as Code | `terraform plan` | infra-automation |
| **git** | Version control (read-only) | `git log --oneline -10` | development |

### Script Execution

| Tool | Description | Example | Tenants |
|------|-------------|---------|---------|
| **safe-python3** | Sandboxed Python | Multi-line Python scripts | default, development |

## Security Model

### Sandboxing with nsjail

The connector uses [nsjail](https://github.com/google/nsjail), Google's security sandbox tool, to isolate command execution:

- **Namespace isolation**: Separate PID, network, mount, and user namespaces
- **Seccomp filtering**: System call filtering to block dangerous operations
- **Resource limits**: cgroups-based CPU, memory, and process limits
- **Read-only root**: Filesystem is mounted read-only (except /tmp)
- **No privilege escalation**: Drops all capabilities, no setuid

### Command Validation

Before execution, commands are validated:

1. **Tool allowlist**: Only tools defined in the tenant policy are allowed
2. **Argument blocking**: Dangerous arguments (e.g., `--upload-file`, `delete`) are blocked
3. **Shell operator blocking**: Operators like `|`, `&`, `;`, `>`, `$()` are rejected
4. **Path traversal prevention**: `..`, absolute paths, and symlink attacks are blocked
5. **Unicode normalization**: Prevents unicode-based bypasses

### Network Isolation

Network access is controlled per-tenant:

| Level | Description |
|-------|-------------|
| **NONE** | No network access (loopback only) |
| **INTERNAL** | Cluster-internal traffic only |
| **RESTRICTED** | Only allowlisted hosts (defined in tenant policy) |
| **FULL** | Any destination (use with caution) |

Metadata endpoints (169.254.169.254, metadata.google.internal) are always blocked.

### Audit Logging

All command executions are logged:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "tenantId": "development",
  "tool": "curl",
  "arguments": "-s https://api.example.com/data",
  "exitCode": 0,
  "durationMs": 1234,
  "resourceUsage": {
    "cpuMillis": 150,
    "memoryMb": 64
  }
}
```

## Output Structure

The connector returns a result object:

```json
{
  "success": true,
  "exitCode": 0,
  "stdout": "command output here",
  "stderr": "",
  "executionTimeMs": 1234,
  "executionId": "exec-abc123",
  "resourceUsage": {
    "cpuMillis": 150,
    "memoryMb": 64
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | true if exitCode is 0 |
| `exitCode` | integer | Process exit code (0 = success) |
| `stdout` | string | Standard output from the command |
| `stderr` | string | Standard error from the command |
| `executionTimeMs` | integer | Execution duration in milliseconds |
| `executionId` | string | Unique execution identifier for audit |
| `resourceUsage.cpuMillis` | integer | CPU time consumed |
| `resourceUsage.memoryMb` | integer | Peak memory usage |

### Result Expression Examples

**Extract just the output:**
```feel
={output: response.stdout}
```

**Parse JSON output:**
```feel
={
  data: response.stdout,
  parsed: if response.success then json(response.stdout) else null,
  error: response.stderr
}
```

**Create status object:**
```feel
={
  success: response.exitCode = 0,
  output: response.stdout,
  duration: response.executionTimeMs,
  memoryUsed: response.resourceUsage.memoryMb
}
```

## Examples

### Process JSON with jq

```
Tenant Profile: Default
CLI Tool: jq
Arguments: '.items[] | {name: .metadata.name, status: .status.phase}'
Input Data: =kubernetesResponse
Network Access: NONE
```

### Fetch API Data

```
Tenant Profile: Development
CLI Tool: curl
Arguments: -s -H "Authorization: Bearer {{secrets.API_TOKEN}}" https://api.example.com/data
Network Access: RESTRICTED
Timeout: 60 seconds
```

### List AWS S3 Buckets

```
Tenant Profile: Cloud Operations
CLI Tool: aws
Arguments: s3 ls --output json
Network Access: RESTRICTED
Memory Limit: 512 MB
```

### Check Kubernetes Pod Status

```
Tenant Profile: Monitoring
CLI Tool: kubectl
Arguments: get pods -n production -o jsonpath='{.items[*].status.phase}'
Network Access: INTERNAL
```

### Terraform Plan

```
Tenant Profile: Infrastructure Automation
CLI Tool: terraform
Arguments: plan -no-color
Network Access: RESTRICTED
Timeout: 300 seconds
Memory Limit: 1024 MB
```

## Common Workflows

Real-world workflow patterns combining multiple connector tasks.

### Workflow 1: API Data Enrichment

Fetch data from an API, transform it, and prepare for downstream processing.

```
┌─────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│  Start  │───▶│  Fetch API   │───▶│  Transform   │───▶│   End   │
│         │    │  (curl)      │    │  (jq)        │    │         │
└─────────┘    └──────────────┘    └──────────────┘    └─────────┘
```

**Task 1: Fetch API (curl)**
```
Tenant: development
Tool: curl
Arguments: -s https://api.example.com/users
Network: RESTRICTED
Result Variable: apiResponse
```

**Task 2: Transform (jq)**
```
Tenant: default
Tool: jq
Arguments: '[.[] | {id: .id, email: .email, active: .status == "active"}]'
Input Data: =apiResponse.stdout
Network: NONE
Result Variable: transformedUsers
```

### Workflow 2: Kubernetes Health Check

Monitor pod status across namespaces and aggregate results.

```
┌─────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│  Start  │───▶│  Get Pods    │───▶│  Analyze     │───▶│   End   │
│         │    │  (kubectl)   │    │  (Python)    │    │         │
└─────────┘    └──────────────┘    └──────────────┘    └─────────┘
```

**Task 1: Get Pods (kubectl)**
```
Tenant: monitoring
Tool: kubectl
Arguments: get pods -A -o json
Network: INTERNAL
Result Variable: podsJson
```

**Task 2: Analyze (Python)**
```
Tenant: default
Mode: script
Tool: safe-python3
Script Content:
import json
data = json.loads(input())
pods = data['items']

summary = {
    'total': len(pods),
    'running': len([p for p in pods if p['status']['phase'] == 'Running']),
    'pending': len([p for p in pods if p['status']['phase'] == 'Pending']),
    'failed': len([p for p in pods if p['status']['phase'] == 'Failed']),
    'namespaces': list(set(p['metadata']['namespace'] for p in pods))
}
summary['healthy'] = summary['running'] == summary['total']

print(json.dumps(summary))

Input Data: =podsJson.stdout
Result Variable: healthStatus
```

### Workflow 3: Cloud Cost Report

Gather cost data from AWS and format for reporting.

```
┌─────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│  Start  │───▶│  Get Costs   │───▶│  Parse JSON  │───▶│  Format      │───▶│   End   │
│         │    │  (aws)       │    │  (jq)        │    │  (Python)    │    │         │
└─────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └─────────┘
```

**Task 1: Get Cost Data (aws)**
```
Tenant: cloud-ops
Tool: aws
Arguments: ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity MONTHLY --metrics BlendedCost --output json
Network: RESTRICTED
Memory: 512 MB
Result Variable: awsCosts
```

**Task 2: Extract Costs (jq)**
```
Tenant: default
Tool: jq
Arguments: '.ResultsByTime[0].Total.BlendedCost'
Input Data: =awsCosts.stdout
Result Variable: costData
```

**Task 3: Format Report (Python)**
```
Tenant: default
Mode: script
Tool: safe-python3
Script Content:
import json
from datetime import datetime

cost = json.loads(input())
amount = float(cost['Amount'])
currency = cost['Unit']

report = {
    'period': 'January 2024',
    'total_cost': round(amount, 2),
    'currency': currency,
    'generated_at': datetime.now().isoformat(),
    'status': 'over_budget' if amount > 10000 else 'within_budget'
}

print(json.dumps(report, indent=2))

Input Data: =costData.stdout
Result Variable: costReport
```

### Workflow 4: GitOps Validation

Validate Kubernetes manifests before deployment.

```
┌─────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│  Start  │───▶│  Validate    │───▶│  Check       │───▶│   End   │
│         │    │  YAML (yq)   │    │  (Python)    │    │         │
└─────────┘    └──────────────┘    └──────────────┘    └─────────┘
```

**Task 1: Parse YAML (yq)**
```
Tenant: default
Tool: yq
Arguments: -o=json '.'
Input Data: =manifestYaml
Result Variable: parsedManifest
```

**Task 2: Validate (Python)**
```
Tenant: default
Mode: script
Tool: safe-python3
Script Content:
import json

manifest = json.loads(input())
errors = []

# Check required fields
if 'apiVersion' not in manifest:
    errors.append('Missing apiVersion')
if 'kind' not in manifest:
    errors.append('Missing kind')
if 'metadata' not in manifest:
    errors.append('Missing metadata')
elif 'name' not in manifest.get('metadata', {}):
    errors.append('Missing metadata.name')

# Check resource limits for Deployments
if manifest.get('kind') == 'Deployment':
    containers = manifest.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
    for i, c in enumerate(containers):
        if 'resources' not in c:
            errors.append(f'Container {i} missing resource limits')

result = {
    'valid': len(errors) == 0,
    'errors': errors,
    'kind': manifest.get('kind'),
    'name': manifest.get('metadata', {}).get('name')
}

print(json.dumps(result))

Input Data: =parsedManifest.stdout
Result Variable: validationResult
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZEEBE_CLIENT_BROKER_GATEWAY-ADDRESS` | Zeebe gateway address | `localhost:26500` |
| `ZEEBE_CLIENT_SECURITY_PLAINTEXT` | Use plaintext connection | `true` |
| `SANDBOX_ENABLED` | Enable sandboxing | `true` |
| `SANDBOX_NSJAIL_PATH` | Path to nsjail binary | `/usr/bin/nsjail` |
| `SANDBOX_DEFAULT_TIMEOUT_SECONDS` | Default timeout | `30` |
| `SANDBOX_DEFAULT_MEMORY_MB` | Default memory limit | `256` |
| `SANDBOX_DEFAULT_TENANT_ID` | Default tenant if none specified | `default` |

### Tenant Policy Configuration

Edit `connector-core/src/main/resources/tenant/policies.yaml` or mount a ConfigMap:

```yaml
tenants:
  - tenantId: my-custom-tenant
    tenantName: Custom Tenant
    enabled: true
    allowedTools:
      - name: curl
        allowedVersions: ["latest"]
        networkAllowed: true
        blockedArguments: ["--upload-file", "-T"]
        seccompProfile: network
      - name: jq
        allowedVersions: ["*"]
        networkAllowed: false
        seccompProfile: strict
    resourceLimits:
      cpuMillis: 1000
      memoryMb: 256
      timeoutSeconds: 60
      maxConcurrent: 5
    networkPolicy:
      egressAllowed: true
      allowedHosts: ["api.example.com"]
      blockedHosts: ["169.254.169.254"]
```

## Monitoring

### Prometheus Metrics

The connector exposes metrics at `/actuator/prometheus`:

| Metric | Type | Description |
|--------|------|-------------|
| `sandbox_connector_executions_total` | Counter | Total executions by tenant, tool, status |
| `sandbox_connector_execution_duration_seconds` | Histogram | Execution duration |
| `sandbox_connector_execution_errors_total` | Counter | Errors by type (timeout, oom, security) |
| `sandbox_connector_resource_usage_cpu_millis` | Gauge | CPU usage per execution |
| `sandbox_connector_resource_usage_memory_mb` | Gauge | Memory usage per execution |

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `/actuator/health` | Overall health |
| `/actuator/health/liveness` | Kubernetes liveness probe |
| `/actuator/health/readiness` | Kubernetes readiness probe |

## Troubleshooting

### Common Errors

#### "Tool 'xyz' is not allowed for tenant"

The selected tool is not in the tenant's allowlist. Either:
- Select a different tenant profile that includes the tool
- Add the tool to the tenant's policy (requires config change)

#### "Argument 'xyz' is blocked for security"

The command includes a blocked argument. Check the tenant policy's `blockedArguments` list. This is a security measure to prevent dangerous operations.

#### "Command execution timed out"

The command exceeded the timeout limit. Either:
- Increase the timeout in the template
- Optimize the command to run faster
- Check for network issues if the command makes external calls

#### "Memory limit exceeded (OOM)"

The command used more memory than allowed. Either:
- Increase the memory limit in the template
- Optimize the command to use less memory
- Process data in smaller chunks

#### "Network access denied"

The command tried to access a blocked network destination. Check:
- The Network Access setting (should be RESTRICTED or FULL for external calls)
- The tenant's `allowedHosts` in the network policy
- The tenant's `blockedHosts` (metadata endpoints are always blocked)

#### "Shell operator blocked"

Commands cannot use shell operators (`|`, `&`, `;`, `>`, etc.) for security. Instead:
- Process data with the tool's built-in features
- Use multiple connector tasks in sequence
- Pass data via stdin using Input Data field

### nsjail Issues

#### "nsjail not working on macOS"

nsjail requires Linux kernel features. On macOS:
1. Use Docker with `--privileged` flag
2. Or use Docker Compose with `privileged: true`

#### "Permission denied" or "Namespace creation failed"

Ensure the container has required capabilities:

```yaml
securityContext:
  privileged: true
  # Or specific capabilities:
  capabilities:
    add:
      - SYS_ADMIN
      - NET_ADMIN
      - SYS_PTRACE
```

For Kubernetes, also check:
```bash
cat /proc/sys/kernel/unprivileged_userns_clone
# Should return 1
```

### Debug Logging

Enable debug logging to see detailed execution information:

```bash
docker run -e LOGGING_LEVEL_IO_CAMUNDA=DEBUG sandbox-connector:latest
```

## Development

### Build

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.9/libexec/openjdk.jdk/Contents/Home
mvn clean package
```

### Run Tests

```bash
mvn test
```

### Build Docker Image

```bash
docker build -f docker/Dockerfile -t sandbox-connector:dev .
```

### Run Locally (Development Only)

```bash
# Note: nsjail won't work on macOS, Linux only
java -jar connector-core/target/sandbox-connector-core-1.0.0-SNAPSHOT.jar
```

## License

Apache License 2.0
