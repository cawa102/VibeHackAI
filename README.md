# VibeHackAI v2

MCP-Integrated Multi-Agent Penetration Testing Support System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

VibeHackAI is an interactive penetration testing support system that leverages Claude Code's agent capabilities and MCP (Model Context Protocol). Four specialized agents (Reconnaissance, Enumeration, Planner, Exploitation) work in coordination with an Orchestrator to execute safe and efficient security assessments under human supervision.

**Important**: This system is designed to support penetration testing with **scope compliance, safety, evidence collection, and reproducibility** as top priorities—not to automate attacks.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Human Interface                          │
│              (Approval, Interaction, Oversight)             │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                 Orchestrator Agent                          │
│            (Control Plane - Single Writer)                  │
│  ┌─────────────┬─────────────┬─────────────┐               │
│  │    State    │  Approval   │    Agent    │               │
│  │  Management │    Gates    │   Routing   │               │
│  └─────────────┴─────────────┴─────────────┘               │
└─────────────────────────────────┬───────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼───────┐   ┌─────────────▼─────────────┐   ┌───────▼───────┐
│ Reconnaissance │   │      Enumeration         │   │   Planner     │
│    Agent      │   │        Agent             │   │    Agent      │
└───────────────┘   └──────────────────────────┘   └───────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Exploitation          │
                    │       Agent               │
                    └──────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                    Shared Workspace                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │State Store │  │Evidence    │  │Retrieval   │            │
│  │(Normalized)│  │Store       │  │Cache       │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                    MCP Servers                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │  GitHub    │  │hexstrike-ai│  │ Filesystem │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### Agent Configuration

| Agent | Role |
|-------|------|
| **Orchestrator** | Control plane responsible for phase transitions, approval gates, and state management |
| **Reconnaissance** | Passive/active information gathering (OSINT, Nmap, Shodan, etc.) |
| **Enumeration** | Service enumeration and vulnerability candidate identification |
| **Planner** | CVE research, attack planning, and CVSS evaluation |
| **Exploitation** | Exploit execution based on approved plans |

### Safety Features

- **Scope Enforcement**: All operations tagged with scope_tag to prevent out-of-scope access
- **Approval Gates**: Dangerous operations require human approval
- **Evidence Management**: All operation results stored in append-only Evidence Store
- **Automatic Stop Conditions**: Auto-halt on consecutive errors or DoS indicators

## Prerequisites

- **Claude Code CLI** (latest version)
- **Docker** (for MCP Server execution)
- **Python 3.10+**
- **hexstrike-ai MCP Server** (penetration testing toolset)

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
```

### 2. MCP Configuration

Copy `.mcp.json.example` to `.mcp.json` and configure appropriately:

```bash
cp .mcp.json.example .mcp.json
```

Set the required environment variables:
- `GITHUB_PERSONAL_ACCESS_TOKEN`: Token for GitHub API
- hexstrike-ai server endpoint configuration

### 3. Install Dependencies

```bash
pip install -e .
```

## Usage

### Starting a Session

1. Launch Claude Code
2. Provide target information (IP/CIDR/Domain)
3. Invoke the Orchestrator agent

```
Please launch pentest-orchestrator.
Target: example.com (192.168.1.0/24)
Scope: Web application assessment
```

### Workflow

1. **Reconnaissance Phase**: Information gathering
2. **Enumeration Phase**: Service and vulnerability enumeration
3. **Planning Phase**: Attack plan development
4. **Exploitation Phase**: Exploit execution after approval
5. **Reporting**: Report generation

Human approval is required between each phase.

## Documentation

For detailed documentation, please refer to:

| Document | Contents |
|----------|----------|
| [CLAUDE.md](CLAUDE.md) | System Guidance (Main) |
| [docs/001_shared_workspace.md](docs/001_shared_workspace.md) | Shared Workspace Specification |
| [docs/002_common_schema.md](docs/002_common_schema.md) | Common Schema Definitions |
| [docs/003_passer.md](docs/003_passer.md) | Normalization Engine Specification |
| [docs/004_patch_protocol.md](docs/004_patch_protocol.md) | Patch Protocol Specification |
| [docs/tool_manifest.yaml](docs/tool_manifest.yaml) | Available Tools List |

### Agent Specifications

| Agent | Specification |
|-------|---------------|
| Orchestrator | [.claude/agents/pentest-orchestrator.md](.claude/agents/pentest-orchestrator.md) |
| Reconnaissance | [.claude/agents/reconnaissance-agent.md](.claude/agents/reconnaissance-agent.md) |
| Enumeration | [.claude/agents/enumeration-agent.md](.claude/agents/enumeration-agent.md) |
| Planner | [.claude/agents/planner-agent.md](.claude/agents/planner-agent.md) |
| Exploitation | [.claude/agents/exploitation-agent.md](.claude/agents/exploitation-agent.md) |

## Important Notes

- Use this system only against **authorized targets**
- Conduct all penetration tests with proper authorization
- Indiscriminate scanning, DoS attacks, and data exfiltration are prohibited

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Issues and Pull Requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
