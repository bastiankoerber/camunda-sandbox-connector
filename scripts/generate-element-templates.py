#!/usr/bin/env python3
"""
Element Template Generator for Sandbox CLI Connector

This script reads tenant policies from policies.yaml and generates:
1. Tenant-specific element templates (one per tenant with only their allowed tools)
2. A combined element template (all tenants, dynamically shows tools based on selection)

Usage:
    python scripts/generate-element-templates.py

Output:
    element-templates/
      sandbox-cli-connector.json              # Combined template (all tenants)
      sandbox-cli-connector-default.json      # Default tenant only
      sandbox-cli-connector-development.json  # Development tenant only
      sandbox-cli-connector-cloud-ops.json    # Cloud-ops tenant only
      ...etc
"""

import json
import yaml
import os
from pathlib import Path
from datetime import datetime

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
POLICIES_FILE = PROJECT_ROOT / "connector-core/src/main/resources/tenant/policies.yaml"
OUTPUT_DIR = PROJECT_ROOT / "element-templates"

# Tool descriptions and tooltips
TOOL_INFO = {
    "jq": {
        "name": "jq - JSON processor",
        "description": "Query and transform JSON data",
        "tooltip": "jq is a lightweight JSON processor. Use it to filter, map, and transform JSON.\n\nExamples:\n- '.items[].name' - Extract all names from items array\n- '.status' - Get status field\n- 'select(.active == true)' - Filter active items"
    },
    "yq": {
        "name": "yq - YAML processor",
        "description": "Query and transform YAML data",
        "tooltip": "yq is like jq but for YAML. Same syntax, different format.\n\nExamples:\n- '.metadata.name' - Get name from metadata\n- '.spec.replicas' - Get replica count"
    },
    "grep": {
        "name": "grep - Pattern matching",
        "description": "Search text using patterns",
        "tooltip": "Search for patterns in text input.\n\nExamples:\n- 'error' - Find lines containing 'error'\n- '-i warning' - Case-insensitive search for 'warning'\n- '-E \"err|warn\"' - Extended regex for multiple patterns"
    },
    "sed": {
        "name": "sed - Stream editor",
        "description": "Transform text streams",
        "tooltip": "Stream editor for text transformations.\n\nExamples:\n- 's/old/new/g' - Replace all occurrences\n- '/pattern/d' - Delete matching lines"
    },
    "awk": {
        "name": "awk - Text processing",
        "description": "Pattern scanning and processing",
        "tooltip": "Powerful text processing language.\n\nExamples:\n- '{print $1}' - Print first column\n- '-F: '{print $1}'' - Split by colon, print first field"
    },
    "safe-python3": {
        "name": "safe-python3 - Secured Python",
        "description": "Python interpreter with security restrictions",
        "tooltip": "Secured Python 3 interpreter. Dangerous modules (os, subprocess, socket, etc.) are blocked.\n\nAllowed modules: json, math, datetime, re, collections, itertools, functools, decimal, fractions, statistics, random, string, textwrap, base64, hashlib, hmac, csv, io\n\nUse for complex data processing that's hard to express in jq."
    },
    "curl": {
        "name": "curl - HTTP client",
        "description": "Transfer data via HTTP/HTTPS",
        "tooltip": "HTTP client for API calls.\n\nExamples:\n- '-s https://api.example.com/health' - GET request\n- '-X POST -d '{\"key\":\"value\"}' -H 'Content-Type: application/json' URL'"
    },
    "http": {
        "name": "http - HTTPie",
        "description": "User-friendly HTTP client",
        "tooltip": "HTTPie - more readable than curl.\n\nExamples:\n- 'GET https://api.example.com'\n- 'POST https://api.example.com key=value'"
    },
    "git": {
        "name": "git - Version control (read-only)",
        "description": "Git operations (status, log, diff)",
        "tooltip": "Git for version control inspection.\n\nAllowed: status, log, diff, show, branch, tag\nBlocked: push, clone, fetch, pull (network operations)"
    },
    "kubectl": {
        "name": "kubectl - Kubernetes CLI",
        "description": "Kubernetes cluster management",
        "tooltip": "Kubernetes CLI for cluster operations.\n\nRead-only examples:\n- 'get pods -n default'\n- 'describe deployment myapp'\n- 'logs myapp-pod-123'\n\nNote: Write operations may be blocked depending on tenant policy."
    },
    "helm": {
        "name": "helm - Helm package manager",
        "description": "Kubernetes package management",
        "tooltip": "Helm for Kubernetes packages.\n\nRead-only examples:\n- 'list -A' - List all releases\n- 'status myrelease' - Get release status\n- 'show values mychart' - Show chart values\n\nNote: Install/upgrade may be blocked depending on tenant policy."
    },
    "gh": {
        "name": "gh - GitHub CLI",
        "description": "GitHub operations",
        "tooltip": "GitHub CLI for repository operations.\n\nExamples:\n- 'pr list' - List pull requests\n- 'issue list' - List issues\n- 'repo view' - View repository info"
    },
    "aws": {
        "name": "aws - AWS CLI",
        "description": "Amazon Web Services CLI",
        "tooltip": "AWS CLI for cloud operations.\n\nExamples:\n- 's3 ls' - List S3 buckets\n- 'ec2 describe-instances' - List EC2 instances\n- 'sts get-caller-identity' - Check credentials\n\nRequires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n\nWARNING: Can modify cloud resources."
    },
    "gcloud": {
        "name": "gcloud - Google Cloud CLI",
        "description": "Google Cloud Platform CLI",
        "tooltip": "GCP CLI for cloud operations.\n\nExamples:\n- 'compute instances list' - List VMs\n- 'storage ls' - List buckets\n- 'projects list' - List projects\n\nRequires: GOOGLE_APPLICATION_CREDENTIALS\n\nWARNING: Can modify cloud resources."
    },
    "az": {
        "name": "az - Azure CLI",
        "description": "Microsoft Azure CLI",
        "tooltip": "Azure CLI for cloud operations.\n\nExamples:\n- 'vm list' - List VMs\n- 'storage account list' - List storage\n- 'account show' - Show subscription\n\nRequires: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID\n\nWARNING: Can modify cloud resources."
    },
    "terraform": {
        "name": "terraform - Infrastructure as Code",
        "description": "Terraform IaC tool",
        "tooltip": "Terraform for infrastructure management.\n\nAllowed operations:\n- 'version' - Show version\n- 'validate' - Validate config\n- 'fmt' - Format config\n- 'plan' - Preview changes\n- 'show' - Show state\n- 'output' - Show outputs\n\nBlocked: apply, destroy, import (for safety)"
    },
    "psql": {
        "name": "psql - PostgreSQL client",
        "description": "PostgreSQL command-line client",
        "tooltip": "PostgreSQL client for database queries.\n\nExamples:\n- '-c \"SELECT * FROM users\"'\n- '-f script.sql'\n\nRequires connection string or environment variables."
    },
    "mysql": {
        "name": "mysql - MySQL client",
        "description": "MySQL command-line client",
        "tooltip": "MySQL client for database queries.\n\nExamples:\n- '-e \"SELECT * FROM users\"'\n- '< script.sql'\n\nRequires connection credentials."
    },
    "redis-cli": {
        "name": "redis-cli - Redis client",
        "description": "Redis command-line client",
        "tooltip": "Redis client for cache operations.\n\nExamples:\n- 'GET mykey'\n- 'KEYS pattern*'\n- 'INFO'"
    },
    "kcat": {
        "name": "kcat - Kafka client",
        "description": "Kafka command-line client",
        "tooltip": "Kafka client (formerly kafkacat).\n\nExamples:\n- '-L -b broker:9092' - List metadata\n- '-C -b broker:9092 -t topic' - Consume messages"
    }
}

# Base template structure
def create_base_template():
    return {
        "$schema": "https://unpkg.com/@camunda/zeebe-element-templates-json-schema/resources/schema.json",
        "name": "Sandbox CLI Connector",
        "id": "io.camunda.connectors.SandboxCLI.v1",
        "version": 7,  # Increment version
        "appliesTo": ["bpmn:Task"],
        "elementType": {"value": "bpmn:ServiceTask"},
        "icon": {
            "contents": "data:image/svg+xml;utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' width='24' height='24'%3E%3Cpath fill='%23333' d='M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 14H4V8h16v10zm-2-1h-6v-2h6v2zM7.5 17l-1.41-1.41L8.67 13l-2.59-2.59L7.5 9l4 4-4 4z'/%3E%3C/svg%3E"
        },
        "description": "Execute CLI commands securely in a sandboxed environment with nsjail isolation",
        "documentationRef": "https://github.com/bastiankoerber/camunda-sandbox-connector#readme",
        "category": {"id": "connectors", "name": "Connectors"},
        "groups": [
            {"id": "tenant", "label": "Security Profile"},
            {"id": "executionMode", "label": "Execution Mode"},
            {"id": "tool", "label": "Tool Selection"},
            {"id": "command", "label": "Command & Input"},
            {"id": "script", "label": "Script Content"},
            {"id": "security", "label": "Security & Resource Limits"},
            {"id": "output", "label": "Output Mapping"},
            {"id": "errors", "label": "Error Handling"}
        ],
        "properties": []
    }


def get_tool_choices(tools):
    """Generate tool choices for dropdown from allowed tools list."""
    choices = []
    for tool in tools:
        tool_name = tool["name"] if isinstance(tool, dict) else tool
        info = TOOL_INFO.get(tool_name, {
            "name": f"{tool_name}",
            "description": f"{tool_name} CLI tool"
        })
        choices.append({
            "name": info["name"],
            "value": tool_name
        })
    return choices


def create_tenant_dropdown(tenants, single_tenant=None):
    """Create tenant selection dropdown."""
    if single_tenant:
        # Hidden field for single-tenant templates
        return {
            "id": "tenantId",
            "type": "Hidden",
            "value": single_tenant["tenantId"],
            "binding": {"type": "zeebe:input", "name": "tenantId"}
        }
    
    # Full dropdown for combined template
    choices = []
    for tenant in tenants:
        if not tenant.get("enabled", True):
            continue
        tools = [t["name"] if isinstance(t, dict) else t for t in tenant.get("allowedTools", [])]
        tool_list = ", ".join(tools[:4])
        if len(tools) > 4:
            tool_list += f", +{len(tools) - 4} more"
        
        choices.append({
            "name": f"{tenant['tenantName']} ({tool_list})",
            "value": tenant["tenantId"]
        })
    
    return {
        "id": "tenantId",
        "label": "Security Profile",
        "description": "Select the security profile that defines available tools and permissions",
        "tooltip": "Each profile has different tools and restrictions:\n\n" + "\n".join([
            f"- {t['tenantName']}: {', '.join([tool['name'] if isinstance(tool, dict) else tool for tool in t.get('allowedTools', [])[:3]])}..."
            for t in tenants if t.get("enabled", True)
        ]),
        "type": "Dropdown",
        "group": "tenant",
        "binding": {"type": "zeebe:input", "name": "tenantId"},
        "value": tenants[0]["tenantId"] if tenants else "default",
        "choices": choices
    }


def create_execution_mode_dropdown():
    """Create execution mode dropdown (command vs script)."""
    return {
        "id": "executionMode",
        "label": "Execution Mode",
        "description": "Choose between CLI command or multi-line script",
        "tooltip": "Choose how to execute code:\n\n- COMMAND: Single CLI command with arguments\n- SCRIPT: Multi-line Python script",
        "type": "Dropdown",
        "group": "executionMode",
        "binding": {"type": "zeebe:input", "name": "executionMode"},
        "value": "command",
        "choices": [
            {"name": "Command - CLI with arguments", "value": "command"},
            {"name": "Script - Multi-line Python", "value": "script"}
        ]
    }


def create_tool_dropdown_for_tenant(tenant, condition_tenant=True):
    """Create tool selection dropdown for a specific tenant."""
    tools = tenant.get("allowedTools", [])
    choices = get_tool_choices(tools)
    
    if not choices:
        return None
    
    # Build tooltip from tool info
    tool_names = [t["name"] if isinstance(t, dict) else t for t in tools]
    tooltip_parts = []
    for name in tool_names:
        info = TOOL_INFO.get(name, {})
        if "tooltip" in info:
            tooltip_parts.append(f"- {name}: {info.get('description', '')}")
    
    tooltip = f"Available tools for {tenant['tenantName']}:\n\n" + "\n".join(tooltip_parts)
    
    prop = {
        "id": f"selectedTool_{tenant['tenantId'].replace('-', '_')}",
        "label": "Tool",
        "description": "Select the CLI tool to execute",
        "tooltip": tooltip,
        "type": "Dropdown",
        "group": "tool",
        "binding": {"type": "zeebe:input", "name": "selectedTool"},
        "value": choices[0]["value"] if choices else "",
        "choices": choices,
        "condition": {
            "allMatch": [
                {"property": "executionMode", "equals": "command"}
            ]
        }
    }
    
    # Add tenant condition for combined template
    if condition_tenant:
        prop["condition"]["allMatch"].insert(0, {"property": "tenantId", "equals": tenant["tenantId"]})
    
    return prop


def create_common_properties():
    """Create properties shared across all templates."""
    return [
        # Hidden task type
        {
            "type": "Hidden",
            "value": "io.camunda:sandbox-cli:1",
            "binding": {"type": "zeebe:taskDefinition", "property": "type"}
        },
        # Hidden action
        {
            "id": "action",
            "type": "Hidden",
            "value": "execute",
            "binding": {"type": "zeebe:input", "name": "action"}
        }
    ]


def create_script_properties():
    """Create script mode properties."""
    return [
        {
            "id": "scriptLanguage",
            "label": "Script Language",
            "description": "Programming language for the script",
            "type": "Dropdown",
            "group": "script",
            "binding": {"type": "zeebe:input", "name": "scriptLanguage"},
            "value": "python",
            "choices": [{"name": "Python", "value": "python"}],
            "condition": {"property": "executionMode", "equals": "script"}
        },
        {
            "id": "scriptContent",
            "label": "Script Content",
            "description": "Multi-line Python script to execute",
            "tooltip": "Enter your Python code. Dangerous modules (os, subprocess, socket) are blocked.\n\nExample:\nimport json\ndata = {'result': 42}\nprint(json.dumps(data))",
            "type": "Text",
            "group": "script",
            "feel": "optional",
            "binding": {"type": "zeebe:input", "name": "scriptContent"},
            "constraints": {"notEmpty": True},
            "condition": {"property": "executionMode", "equals": "script"}
        },
        {
            "id": "allowedToolsForScript",
            "type": "Hidden",
            "value": "=[\"safe-python3\"]",
            "binding": {"type": "zeebe:input", "name": "allowedTools"},
            "condition": {"property": "executionMode", "equals": "script"}
        }
    ]


def create_command_properties():
    """Create command mode properties."""
    return [
        {
            "id": "allowedTools",
            "type": "Hidden",
            "value": "=[selectedTool]",
            "binding": {"type": "zeebe:input", "name": "allowedTools"},
            "condition": {"property": "executionMode", "equals": "command"}
        },
        {
            "id": "commandArguments",
            "label": "Arguments",
            "description": "Command arguments (tool name is added automatically)",
            "tooltip": "Enter ONLY the arguments, NOT the tool name.\n\nExamples:\n- jq: '.items[].name'\n- curl: '-s https://api.example.com'\n- kubectl: 'get pods -n default'",
            "type": "Text",
            "group": "command",
            "feel": "optional",
            "binding": {"type": "zeebe:input", "name": "commandArguments"},
            "constraints": {"notEmpty": True},
            "condition": {"property": "executionMode", "equals": "command"}
        },
        {
            "id": "command",
            "type": "Hidden",
            "value": "=selectedTool + \" \" + commandArguments",
            "binding": {"type": "zeebe:input", "name": "command"},
            "condition": {"property": "executionMode", "equals": "command"}
        },
        {
            "id": "inputData",
            "label": "Input Data (stdin)",
            "description": "Data to pass to the command via stdin",
            "tooltip": "Data piped to stdin. Use FEEL (=variableName) for process variables.",
            "type": "Text",
            "group": "command",
            "feel": "optional",
            "optional": True,
            "binding": {"type": "zeebe:input", "name": "inputData"},
            "condition": {"property": "executionMode", "equals": "command"}
        },
        {
            "id": "environment",
            "label": "Environment Variables",
            "description": "Additional environment variables as JSON",
            "tooltip": "JSON object with env vars: {\"KEY\": \"value\"}\n\nFor secrets: {\"KEY\": \"{{secrets.MY_SECRET}}\"}",
            "type": "Text",
            "group": "command",
            "feel": "optional",
            "optional": True,
            "binding": {"type": "zeebe:input", "name": "environment"}
        }
    ]


def create_security_properties(tenant=None):
    """Create security and resource limit properties."""
    # Use tenant limits for defaults if provided
    limits = tenant.get("resourceLimits", {}) if tenant else {}
    default_timeout = str(limits.get("timeoutSeconds", 30))
    default_memory = str(limits.get("memoryMb", 256))
    
    # Determine max values from tenant policy
    max_timeout = limits.get("timeoutSeconds", 300)
    max_memory = limits.get("memoryMb", 1024)
    
    timeout_choices = [
        {"name": "10 seconds", "value": "10"},
        {"name": "30 seconds", "value": "30"},
        {"name": "60 seconds", "value": "60"},
        {"name": "120 seconds", "value": "120"},
        {"name": "300 seconds", "value": "300"},
    ]
    # Filter to max allowed
    timeout_choices = [c for c in timeout_choices if int(c["value"]) <= max_timeout]
    
    memory_choices = [
        {"name": "128 MB", "value": "128"},
        {"name": "256 MB", "value": "256"},
        {"name": "512 MB", "value": "512"},
        {"name": "1024 MB", "value": "1024"},
    ]
    # Filter to max allowed
    memory_choices = [c for c in memory_choices if int(c["value"]) <= max_memory]
    
    network_policy = tenant.get("networkPolicy", {}) if tenant else {}
    network_choices = [{"name": "None - No network access", "value": "NONE"}]
    
    if network_policy.get("egressAllowed", False):
        network_choices.extend([
            {"name": "Internal - Cluster only", "value": "INTERNAL"},
            {"name": "Restricted - Allowlisted hosts", "value": "RESTRICTED"},
            {"name": "Full - Any destination", "value": "FULL"}
        ])
    
    return [
        {
            "id": "networkAccess",
            "label": "Network Access",
            "description": "Network isolation level",
            "type": "Dropdown",
            "group": "security",
            "binding": {"type": "zeebe:input", "name": "networkAccess"},
            "value": "NONE" if not network_policy.get("egressAllowed") else "RESTRICTED",
            "choices": network_choices
        },
        {
            "id": "timeoutSeconds",
            "label": "Timeout",
            "description": f"Maximum execution time (max: {max_timeout}s for this profile)",
            "type": "Dropdown",
            "group": "security",
            "binding": {"type": "zeebe:input", "name": "timeoutSeconds"},
            "value": default_timeout if default_timeout in [c["value"] for c in timeout_choices] else timeout_choices[-1]["value"],
            "choices": timeout_choices
        },
        {
            "id": "memoryLimitMb",
            "label": "Memory Limit",
            "description": f"Maximum RAM (max: {max_memory}MB for this profile)",
            "type": "Dropdown",
            "group": "security",
            "binding": {"type": "zeebe:input", "name": "memoryLimitMb"},
            "value": default_memory if default_memory in [c["value"] for c in memory_choices] else memory_choices[-1]["value"],
            "choices": memory_choices
        }
    ]


def create_output_properties():
    """Create output mapping properties."""
    return [
        {
            "id": "resultVariable",
            "label": "Result Variable",
            "description": "Variable to store the execution result",
            "tooltip": "The result object contains:\n- stdout, stderr, exitCode, success, executionTimeMs, resourceUsage",
            "type": "String",
            "group": "output",
            "binding": {"type": "zeebe:taskHeader", "key": "resultVariable"},
            "value": "sandboxResult"
        },
        {
            "id": "resultExpression",
            "label": "Result Expression",
            "description": "FEEL expression to transform the result",
            "type": "Text",
            "group": "output",
            "feel": "required",
            "optional": True,
            "binding": {"type": "zeebe:taskHeader", "key": "resultExpression"}
        }
    ]


def create_error_properties():
    """Create error handling properties."""
    return [
        {
            "id": "errorHandling",
            "label": "Error Handling",
            "description": "How to handle CLI failures",
            "type": "Dropdown",
            "group": "errors",
            "binding": {"type": "zeebe:taskHeader", "key": "errorHandlingMode"},
            "value": "ignore",
            "choices": [
                {"name": "Ignore - Handle in process", "value": "ignore"},
                {"name": "Throw BPMN Error", "value": "throwError"},
                {"name": "Custom expression", "value": "custom"}
            ]
        },
        {
            "id": "errorExpressionAuto",
            "type": "Hidden",
            "value": "=if response.exitCode != 0 then bpmnError(\"CLI_ERROR\", response.stderr) else null",
            "binding": {"type": "zeebe:taskHeader", "key": "errorExpression"},
            "condition": {"property": "errorHandling", "equals": "throwError"}
        },
        {
            "id": "errorExpressionCustom",
            "label": "Error Expression",
            "description": "Custom FEEL expression for error handling",
            "type": "Text",
            "group": "errors",
            "feel": "required",
            "optional": True,
            "binding": {"type": "zeebe:taskHeader", "key": "errorExpression"},
            "condition": {"property": "errorHandling", "equals": "custom"}
        },
        {
            "id": "retries",
            "label": "Retries",
            "description": "Automatic retry count",
            "type": "Dropdown",
            "group": "errors",
            "binding": {"type": "zeebe:taskDefinition", "property": "retries"},
            "value": "3",
            "choices": [
                {"name": "0 - No retries", "value": "0"},
                {"name": "1", "value": "1"},
                {"name": "3 - Default", "value": "3"},
                {"name": "5", "value": "5"}
            ]
        }
    ]


def generate_combined_template(tenants):
    """Generate combined template with all tenants."""
    template = create_base_template()
    template["name"] = "Sandbox CLI Connector"
    template["description"] = "Execute CLI commands securely in a sandboxed environment with nsjail isolation"
    
    props = create_common_properties()
    props.append(create_tenant_dropdown(tenants))
    props.append(create_execution_mode_dropdown())
    
    # Add tool dropdown for each tenant (conditional)
    for tenant in tenants:
        if tenant.get("enabled", True):
            tool_dropdown = create_tool_dropdown_for_tenant(tenant, condition_tenant=True)
            if tool_dropdown:
                props.append(tool_dropdown)
    
    props.extend(create_script_properties())
    props.extend(create_command_properties())
    props.extend(create_security_properties())
    props.extend(create_output_properties())
    props.extend(create_error_properties())
    
    template["properties"] = props
    return template


def generate_tenant_template(tenant):
    """Generate template for a single tenant."""
    template = create_base_template()
    template["name"] = f"Sandbox CLI - {tenant['tenantName']}"
    template["id"] = f"io.camunda.connectors.SandboxCLI.{tenant['tenantId'].replace('-', '_')}.v1"
    
    # Build description with allowed tools
    tools = [t["name"] if isinstance(t, dict) else t for t in tenant.get("allowedTools", [])]
    template["description"] = f"Execute {', '.join(tools[:3])}{'...' if len(tools) > 3 else ''} in sandboxed environment ({tenant['tenantName']} profile)"
    
    props = create_common_properties()
    props.append(create_tenant_dropdown([], single_tenant=tenant))
    props.append(create_execution_mode_dropdown())
    
    # Single tool dropdown (no tenant condition needed)
    tool_dropdown = create_tool_dropdown_for_tenant(tenant, condition_tenant=False)
    if tool_dropdown:
        props.append(tool_dropdown)
    
    props.extend(create_script_properties())
    props.extend(create_command_properties())
    props.extend(create_security_properties(tenant))
    props.extend(create_output_properties())
    props.extend(create_error_properties())
    
    template["properties"] = props
    return template


def main():
    print(f"Loading policies from: {POLICIES_FILE}")
    
    with open(POLICIES_FILE, 'r') as f:
        policies = yaml.safe_load(f)
    
    tenants = policies.get("tenants", [])
    enabled_tenants = [t for t in tenants if t.get("enabled", True)]
    
    print(f"Found {len(tenants)} tenants, {len(enabled_tenants)} enabled")
    
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate combined template
    combined = generate_combined_template(enabled_tenants)
    combined_file = OUTPUT_DIR / "sandbox-cli-connector.json"
    with open(combined_file, 'w') as f:
        json.dump(combined, f, indent=2)
    print(f"Generated: {combined_file}")
    
    # Generate per-tenant templates
    for tenant in enabled_tenants:
        tenant_template = generate_tenant_template(tenant)
        tenant_file = OUTPUT_DIR / f"sandbox-cli-connector-{tenant['tenantId']}.json"
        with open(tenant_file, 'w') as f:
            json.dump(tenant_template, f, indent=2)
        print(f"Generated: {tenant_file}")
    
    print(f"\nDone! Generated {1 + len(enabled_tenants)} element templates")
    print(f"\nTo use in Camunda Modeler:")
    print(f"  1. Copy files from {OUTPUT_DIR} to your Modeler's element-templates folder")
    print(f"  2. Restart Modeler or refresh templates")


if __name__ == "__main__":
    main()
