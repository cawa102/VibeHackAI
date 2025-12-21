# Installation Guide

Complete setup guide for using VibeHackAI with Claude Code.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [MCP Server Setup](#mcp-server-setup)
- [Claude Code Configuration](#claude-code-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Overview

VibeHackAI is designed to work with [Claude Code](https://claude.ai/code). The architecture consists of:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Claude Code   │───▶│   VibeHackAI    │───▶│   MCP Servers   │
│   (AI Brain)    │    │   (Framework)   │    │   (Tools)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

- **Claude Code**: Provides AI reasoning, analysis, and decision-making
- **VibeHackAI**: Provides workflow structure and safety controls
- **MCP Servers**: Provide security tools (Nmap, Shodan, Metasploit, etc.)

## Requirements

### Required

| Requirement | Version | Purpose |
|-------------|---------|---------|
| [Claude Code](https://claude.ai/code) | Latest | AI reasoning engine |
| Node.js | 18+ | MCP server runtime |
| Git | 2.0+ | Clone repository |

### Optional (for advanced features)

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Docker | 20.10+ | GitHub MCP server |
| Java | 11+ | Burp Suite MCP |
| Metasploit Framework | 6.0+ | Exploitation features |
| Python | 3.10+ | Development/testing |

### API Keys

| Service | Required | Get API Key |
|---------|----------|-------------|
| Shodan | Recommended | [account.shodan.io](https://account.shodan.io/) |
| Snyk | Optional | [app.snyk.io/account](https://app.snyk.io/account) |
| GitHub | Optional | [github.com/settings/tokens](https://github.com/settings/tokens) |
| WhoisXML API | Optional | [whoisxmlapi.com](https://whoisxmlapi.com/) |

## Quick Start

### Step 1: Clone Repository

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
```

### Step 2: Install MCP Servers

Install the minimum required MCP servers:

```bash
# Verify Node.js is installed
node --version  # Should be 18+

# Install nmap (required for scanning)
# macOS:
brew install nmap

# Ubuntu/Debian:
sudo apt-get install nmap

# Windows:
# Download from https://nmap.org/download.html
```

### Step 3: Configure API Keys

Edit `.mcp.json` in the repository root and replace placeholder values:

```json
{
  "mcpServers": {
    "shodan": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "YOUR_ACTUAL_API_KEY_HERE"
      }
    }
  }
}
```

### Step 4: Open in Claude Code

```bash
# Open Claude Code in the VibeHackAI directory
claude code .

# Or if already in Claude Code, navigate to the directory
```

### Step 5: Start Penetration Test

In Claude Code, type:

```
I have written authorization to test [YOUR_TARGET].
Please perform a penetration test following the VibeHackAI workflow.
```

---

## MCP Server Setup

### Tier 1: Essential (Recommended)

These servers provide core functionality:

#### Filesystem MCP

Allows file operations in workspace.

```bash
# Runs automatically via npx
npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

`.mcp.json` configuration:
```json
{
  "filesystem": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "./workspace"]
  }
}
```

#### Nmap MCP

Port scanning and service detection.

```bash
# Install nmap first (see Step 2 above)
# MCP server runs via npx
npx -y mcp-nmap-server
```

`.mcp.json` configuration:
```json
{
  "nmap": {
    "command": "npx",
    "args": ["-y", "mcp-nmap-server"]
  }
}
```

#### Shodan MCP

Passive reconnaissance without touching target.

```bash
# Get API key from https://account.shodan.io/
npx -y @burtthecoder/mcp-shodan
```

`.mcp.json` configuration:
```json
{
  "shodan": {
    "command": "npx",
    "args": ["-y", "@burtthecoder/mcp-shodan"],
    "env": {
      "SHODAN_API_KEY": "your-api-key"
    }
  }
}
```

### Tier 2: Vulnerability Research

#### Snyk MCP

Vulnerability database lookups.

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate (creates token automatically)
snyk auth

# Or set token directly from https://app.snyk.io/account
```

`.mcp.json` configuration:
```json
{
  "snyk": {
    "command": "snyk",
    "args": ["test", "--json"],
    "env": {
      "SNYK_TOKEN": "your-snyk-token"
    }
  }
}
```

#### CVE-Search MCP

Search CVE databases.

```bash
# Clone CVE-Search MCP (if available)
git clone https://github.com/example/cve-search-mcp external/cve-search-mcp
cd external/cve-search-mcp
uv sync
```

`.mcp.json` configuration:
```json
{
  "cve-search": {
    "command": "uv",
    "args": ["--directory", "./external/cve-search-mcp", "run", "main.py"]
  }
}
```

### Tier 3: Git Integration

#### GitHub MCP

Repository and code analysis.

```bash
# Requires Docker
# Get token from https://github.com/settings/tokens
# Required scopes: repo, read:org
```

`.mcp.json` configuration:
```json
{
  "github": {
    "command": "docker",
    "args": [
      "run", "-i", "--rm",
      "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
      "ghcr.io/github/github-mcp-server"
    ],
    "env": {
      "GITHUB_PERSONAL_ACCESS_TOKEN": "your-github-token"
    }
  }
}
```

#### GitLab MCP

```json
{
  "gitlab": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "https://gitlab.com/api/v4/mcp"]
  }
}
```

### Tier 4: Exploitation (Advanced)

> **Warning**: These tools can cause damage. Only use with explicit authorization.

#### Metasploit MCP

```bash
# Install Metasploit Framework
# https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html

# Start Metasploit RPC server
msfrpcd -P your_password -S -f

# Clone Metasploit MCP
git clone https://github.com/example/MetasploitMCP external/MetasploitMCP
```

`.mcp.json` configuration:
```json
{
  "metasploit": {
    "command": "python",
    "args": ["./external/MetasploitMCP/MetasploitMCP.py", "--transport", "stdio"],
    "env": {
      "MSF_PASSWORD": "your-password",
      "MSF_SERVER": "127.0.0.1",
      "MSF_PORT": "55553",
      "MSF_SSL": "false"
    }
  }
}
```

#### Burp Suite MCP

Requires Burp Suite Professional.

```bash
# Download Burp MCP Proxy extension
# Configure in Burp Suite
# Start proxy server
java -jar /path/to/burp-mcp-proxy.jar --sse-url http://127.0.0.1:9876
```

`.mcp.json` configuration:
```json
{
  "burpsuite": {
    "command": "java",
    "args": ["-jar", "/path/to/burp-mcp-proxy.jar", "--sse-url", "http://127.0.0.1:9876"]
  }
}
```

---

## Claude Code Configuration

### Option A: Project-Level Configuration (Recommended)

Keep `.mcp.json` in the VibeHackAI repository root. Claude Code automatically detects it.

```
VibeHackAI/
├── .mcp.json          ← MCP configuration
├── CLAUDE.md          ← Project instructions for Claude
├── README.md
└── ...
```

### Option B: Global Configuration

Add to your Claude Code global settings for use across projects.

### Minimal Working Configuration

For basic reconnaissance, you only need:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "nmap": {
      "command": "npx",
      "args": ["-y", "mcp-nmap-server"]
    },
    "shodan": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key"
      }
    }
  }
}
```

### Full Configuration

See `.mcp.json` in the repository for complete configuration with all supported MCP servers.

---

## Verification

### Check MCP Server Availability

In Claude Code, ask:

```
What MCP tools are available?
```

Claude should list the configured servers (filesystem, nmap, shodan, etc.).

### Test Basic Functionality

```
Use Shodan to look up information about 8.8.8.8
```

Expected: Claude uses the Shodan MCP to query host information.

### Test Nmap Scanning

```
I have authorization to scan my local machine (127.0.0.1).
Please perform a basic port scan.
```

Expected: Claude uses Nmap MCP to scan and reports open ports.

---

## Troubleshooting

### MCP Server Not Found

**Symptom**: Claude says it can't find a tool

**Solution**:
1. Check `.mcp.json` is in the project root
2. Verify JSON syntax is valid
3. Restart Claude Code after configuration changes

### npx Errors

**Symptom**: "npx: command not found" or package install fails

**Solution**:
```bash
# Verify Node.js installation
node --version
npm --version

# Clear npx cache
npx clear-npx-cache
```

### API Key Issues

**Symptom**: "Unauthorized" or "Invalid API key" errors

**Solution**:
1. Verify API key is correct (no extra spaces)
2. Check API key permissions/scopes
3. Ensure environment variable is properly quoted in `.mcp.json`

### Nmap Permission Denied

**Symptom**: Nmap fails with permission error

**Solution**:
```bash
# Linux: Grant raw socket capability
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

# Or run specific scans that don't require root
# (TCP connect scan instead of SYN scan)
```

### Docker Issues (GitHub MCP)

**Symptom**: GitHub MCP fails to start

**Solution**:
```bash
# Verify Docker is running
docker info

# Pull image manually
docker pull ghcr.io/github/github-mcp-server

# Check Docker permissions
# User should be in docker group
```

### Metasploit Connection Failed

**Symptom**: Cannot connect to MSFRPC

**Solution**:
```bash
# Verify msfrpcd is running
netstat -an | grep 55553

# Restart msfrpcd
msfrpcd -P your_password -S -f

# Check password matches .mcp.json
```

---

## Development Setup (Optional)

For contributors who want to run tests or modify the codebase:

```bash
# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src/
mypy src/
```

---

## Next Steps

1. Read [README.md](README.md) for usage examples
2. Review [SECURITY.md](SECURITY.md) for safety guidelines
3. Check [CLAUDE.md](CLAUDE.md) for project specifications
4. Join [GitHub Discussions](https://github.com/cawa102/VibeHackAI/discussions) for community support
