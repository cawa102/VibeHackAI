# Examples

This directory contains example configurations and usage scenarios for PentestAgent.

## Contents

- [basic_scan.md](#basic-scan) - Basic reconnaissance workflow
- [web_app_pentest.md](#web-application-pentest) - Web application testing
- [scope_example.json](#scope-configuration) - Example scope configuration
- [mcp_minimal.json](#minimal-mcp-setup) - Minimal MCP configuration

## Basic Scan

A simple workflow for reconnaissance of a target network.

### Prerequisites

- Nmap MCP server running
- Target authorization obtained

### Steps

```bash
# Start PentestAgent
pentest-agent

# Create session
> start basic-recon-session

# Define scope
> scope
Add target type [ip/cidr/domain]: cidr
Add target value: 192.168.1.0/24
Add another target? [y/N]: n
Confirm scope? [y/N]: y

# Run reconnaissance
> run

# View findings
> findings

# Export report
> export report.md
```

## Web Application Pentest

Complete workflow for web application security testing.

### Prerequisites

- Burp Suite MCP running
- Target web application authorized
- Nmap and OSINT MCPs available

### Steps

```bash
# Start session
> start webapp-test

# Define scope for web application
> scope
Add target type [ip/cidr/domain]: domain
Add target value: testapp.example.com
Add allowed operation: web_scan
Add allowed operation: api_test
Confirm scope? [y/N]: y

# Phase 1: Reconnaissance
> run
# Gathers DNS, WHOIS, technology stack info

# Phase 2: Enumeration (auto-advances or manual)
> advance
> run
# Discovers endpoints, parameters, auth mechanisms

# Phase 3: Planning
> advance
> run
# Analyzes for vulnerabilities, creates exploitation plan

# Phase 4: Exploitation (requires approval)
> advance
> run
# You will be prompted to approve each exploit attempt

# Generate report
> export webapp-report.md
```

## Scope Configuration

Example `scope.json` for authorized testing:

```json
{
  "session_id": "webapp-test-001",
  "scope_tag": "authorized-test-2025",
  "targets": [
    {
      "type": "domain",
      "value": "testapp.example.com"
    },
    {
      "type": "ip",
      "value": "192.168.1.100"
    },
    {
      "type": "cidr",
      "value": "10.0.0.0/24"
    }
  ],
  "allowed_operations": [
    "passive_recon",
    "active_scan",
    "web_scan",
    "api_test",
    "vuln_scan"
  ],
  "excluded_targets": [
    "192.168.1.1",
    "production.example.com"
  ],
  "restrictions": {
    "no_dos": true,
    "no_brute_force": true,
    "max_requests_per_second": 10
  },
  "authorization": {
    "document_ref": "pentest-auth-2025-001.pdf",
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2025-01-31T23:59:59Z",
    "authorizer": "Security Team Lead"
  }
}
```

## Minimal MCP Setup

Minimal `.mcp.json` for basic functionality:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "./workspace"
      ]
    },
    "nmap": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-nmap-server"
      ]
    }
  }
}
```

## Full MCP Setup

Complete `.mcp.json` with all integrations:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./workspace"]
    },
    "nmap": {
      "command": "npx",
      "args": ["-y", "mcp-nmap-server"]
    },
    "shodan": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "${SHODAN_API_KEY}"
      }
    },
    "github": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "ghcr.io/github/github-mcp-server"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
      }
    },
    "metasploit": {
      "command": "python",
      "args": ["external/MetasploitMCP/MetasploitMCP.py", "--transport", "stdio"],
      "env": {
        "MSF_PASSWORD": "${MSF_PASSWORD}",
        "MSF_SERVER": "127.0.0.1",
        "MSF_PORT": "55553"
      }
    }
  }
}
```

## Environment Variables Template

Create a `.env` file:

```bash
# OSINT APIs
SHODAN_API_KEY=your_shodan_api_key
WHOISXMLAPI_API_KEY=your_whoisxmlapi_key

# Vulnerability Research
SNYK_TOKEN=your_snyk_token

# Git Integration
GITHUB_PERSONAL_ACCESS_TOKEN=your_github_token

# Metasploit
MSF_PASSWORD=your_msf_password
MSF_SERVER=127.0.0.1
MSF_PORT=55553
MSF_SSL=false

# Burp Suite
BURP_MCP_PROXY_JAR_PATH=/path/to/burp-mcp-proxy.jar
```

## CLI Commands Reference

| Command | Description |
|---------|-------------|
| `start [session]` | Start new or resume session |
| `scope` | View/edit scope configuration |
| `run` | Execute current phase agent |
| `advance` | Move to next phase |
| `phase` | Show current phase details |
| `findings` | List discovered findings |
| `evidence [id]` | View evidence details |
| `status` | Show orchestrator status |
| `export [file]` | Export report |
| `exit` | Exit CLI |

## Approval Prompts

When dangerous operations are requested, you'll see:

```
[APPROVAL REQUIRED]
Operation: metasploit_exploit
Module: exploit/multi/http/apache_mod_cgi_bash_env_exec
Target: 192.168.1.100:80

Risk Level: HIGH
Description: Shellshock (CVE-2014-6271) exploitation attempt

Approve this operation? [y/N]:
```

Always review carefully before approving.

## Tips

1. **Start small**: Begin with passive reconnaissance
2. **Review findings**: Check findings before advancing phases
3. **Document everything**: Evidence is automatically collected
4. **Stay in scope**: Never test unauthorized targets
5. **Use approval wisely**: Review each approval request carefully
