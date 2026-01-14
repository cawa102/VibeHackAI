<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00fff2,20:00b4d8,40:7b2cbf,70:c71585,100:ff00ff&height=180&section=header&text=VibeHackAI%E3%80%80v2.0&fontSize=42&fontColor=fff&animation=fadeIn&fontAlignY=32&desc=AI-Assisted%20Penetration%20Testing%20Framework&descSize=16&descAlignY=52&descColor=00ffff"/>

<br/>

[![CI](https://img.shields.io/github/actions/workflow/status/cawa102/VibeHackAI/ci.yml?style=flat-square&logo=github&label=build)](https://github.com/cawa102/VibeHackAI/actions)
[![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-early_development-orange?style=flat-square)](https://github.com/cawa102/VibeHackAI)

**🔍 Reconnaissance** · **📋 Enumeration** · **⚡ Exploitation** · **🛡️ Human Control**

</div>

## Overview

This system provides an agentic AI experience as if you were leading an Penetration Test Team!

VibeHackAI is an interactive penetration testing support system that leverages Claude Code's agent capabilities and MCP (Model Context Protocol). Four specialized agents (Planner, Reconnaissance, Enumeration, Exploitation) work in coordination with an Orchestrator to execute safe and efficient security assessments under human supervision.

### Two key differentiators

1. **vs. Autonomous penetration tools** — VibeHackAI combines AI and human reasoning to prevent uncontrolled AI behavior. The human reviews the AI's plan, validates the logic, and provides course corrections before any action is taken.

2. **vs. PentestGPT-style tools** — While PentestGPT requires humans to manually type and execute every command, VibeHackAI's AI handles command execution across all testing phases. Humans focus on strategic decisions rather than operational details.

**The result:** Higher success rates through collaborative intelligence. Humans contribute domain expertise and judgment; AI contributes speed, consistency, and comprehensive analysis. Neither works alone—both work together.

### Why Human-in-the-Loop?

Fully autonomous penetration testing tools face fundamental limitations:

| Problem | Impact |
|---------|--------|
| Scope violations | AI scans unrelated hosts without understanding authorization boundaries |
| False confidence | AI reports "confirmed" vulnerabilities that don't exist |
| Dangerous actions | AI executes destructive payloads without understanding consequences |
| Context loss | AI forgets previous findings and repeats failed approaches |

VibeHackAI addresses these issues by keeping humans in the decision loop. The AI handles analysis and suggestions; you make the final call on every significant action.

## Architecture

```
               ┌──────────────────────────────────────────────────────┐
               │                   Human Interface                    │
               │          (Approval, Interaction, Oversight)          │
               └──────────────────────────┬───────────────────────────┘
                                          │          
               ┌──────────────────────────▼────────────────────────────┐
               │                  Orchestrator Agent                   │         　┌──────────────────────────────────────────────────┐          
               │                (Control Plane - Writer)               │        　 │                Shared Workspace                  │
               │      ┌─────────────┬─────────────┬─────────────┐      │        　 │  ┌────────────┐  ┌────────────┐  ┌────────────┐  │
               │      │    State    │  Approval   │    Agent    │      │ ───────▶︎ │  │State Store │  │Evidence    │  │Retrieval   │  │
               │      │  Management │    Gates    │   Routing   │      │         　│  │(Normalized)│  │Store       │  │Cache       │  │
               │      └─────────────┴─────────────┴─────────────┘      │      　   │  └────────────┘  └────────────┘  └────────────┘  │
               └──────────────────────────┬────────────────────────────┘   　      └──────────────────────────────────────────────────┘
                                          │
        ┌──────────────────────┬────────────────────┬────────────────────┐
        │                      │                    │                    │
┌───────▼────────┐   ┌─────────▼────────┐   ┌───────▼────────┐   ┌───────▼───────┐
│ Reconnaissance │   │   Enumeration    │   │  Exploitation  │   │    Planner    │
│     Agent      │   │      Agent       │   │      Agent     │   │     Agent     │
└────────────────┘   └──────────────────┘   └────────────────┘   └───────────────┘

```

## ✨ Key Features

### 🤖 Agent Configuration

| Agent | Role |
|-------|------|
| **Orchestrator** | Control plane responsible for phase transitions, approval gates, and state management |
| **Planner** | CVE research, attack planning, and CVSS evaluation |
| **Reconnaissance** | Passive/active information gathering (OSINT, Nmap, Shodan, etc.) |
| **Enumeration** | Service enumeration and vulnerability candidate identification |
| **Exploitation** | Exploit execution based on approved plans |

### 🛡️ Safety Features

- **Scope Enforcement**: All operations tagged with scope_tag to prevent out-of-scope access
- **Approval Gates**: Dangerous operations require human approval
- **Evidence Management**: All operation results stored in append-only Evidence Store
- **Automatic Stop Conditions**: Auto-halt on consecutive errors or DoS indicators

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
cp .mcp.json.example .mcp.json
pip install -e .

# Launch Claude Code and start
Please launch pentest-orchestrator.
Target: example.com
Scope: Web application assessment
```

## 📋 Prerequisites

| Requirement | Version | Link |
|-------------|---------|------|
| Claude Code CLI | Latest | [Installation Guide](https://docs.anthropic.com/en/docs/claude-code) |
| Docker | Latest | [docker.com](https://www.docker.com/) |
| Python | 3.10+ | [python.org](https://www.python.org/) |
| hexstrike-ai MCP Server | Required | [**Setup Guide ↗**](https://github.com/0x4m4/hexstrike-ai) |

> **Important**: hexstrike-ai MCP Server must be set up before using VibeHackAI.
> 👉 Follow the instructions at [github.com/0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai)

## 🔧 Setup

<details>
<summary><b>1. Setup hexstrike-ai MCP Server</b></summary>

First, set up the hexstrike-ai MCP server by following the instructions at:

👉 **[https://github.com/0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai)**

Make sure the server is running before proceeding.
</details>

<details>
<summary><b>2. Clone the Repository</b></summary>

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
```
</details>

<details>
<summary><b>3. MCP Configuration</b></summary>

Copy `.mcp.json.example` to `.mcp.json` and configure appropriately:

```bash
cp .mcp.json.example .mcp.json
```

Set the required environment variables:
- `GITHUB_PERSONAL_ACCESS_TOKEN`: Token for GitHub API
- hexstrike-ai server endpoint configuration (see [hexstrike-ai docs](https://github.com/0x4m4/hexstrike-ai))
</details>

<details>
<summary><b>4. Install Dependencies</b></summary>

```bash
pip install -e .
```
</details>

## 💡 Usage

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

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                                                             │
    ╔═══════════════╗               │    ╔═══════════════╗         ╔═══════════════╗             │
    ║   👤 Human    ║───Target───▶──┼──▶║ 🎯 Orchestrator║────────▶║  📝 Planner   ║             │
    ╚═══════════════╝               │    ╚═══════════════╝         ╚═══════════════╝             │
            │                       │            │                         │                     │
            │                       │            │                         │                     │
    ┌───────▼───────┐               │    ┌───────▼───────┐         ┌───────▼───────┐             │
    │   Approval    │◀──PhaseBrief──┼────│  State Mgmt   │◀─Patch──│   TestPlan    │             │
    └───────────────┘               │    └───────────────┘         └───────────────┘             │
                                    │                                                             │
                                    └─────────────────────────────────────────────────────────────┘
                                                          │
                         ┌────────────────────────────────┼────────────────────────────────┐
                         │                                │                                │
                         ▼                                ▼                                ▼
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃    🔍 RECONNAISSANCE      ┃    ┃    📋 ENUMERATION         ┃    ┃    ⚡ EXPLOITATION        ┃
    ┃  ┌─────────────────────┐  ┃    ┃  ┌─────────────────────┐  ┃    ┃  ┌─────────────────────┐  ┃
    ┃  │ • OSINT / Shodan    │  ┃    ┃  │ • Service Analysis  │  ┃    ┃  │ • PoC Execution     │  ┃
    ┃  │ • Nmap Scanning     │  ┃    ┃  │ • Entry Points      │  ┃    ┃  │ • Metasploit        │  ┃
    ┃  │ • DNS Enumeration   │  ┃    ┃  │ • Auth Boundaries   │  ┃    ┃  │ • Custom Payloads   │  ┃
    ┃  └─────────────────────┘  ┃    ┃  └─────────────────────┘  ┃    ┃  └─────────────────────┘  ┃
    ┃           │               ┃    ┃           │               ┃    ┃           │               ┃
    ┃     ┌─────▼─────┐         ┃    ┃     ┌─────▼─────┐         ┃    ┃     ┌─────▼─────┐         ┃
    ┃     │  Result?  │         ┃    ┃     │  Result?  │         ┃    ┃     │  Result?  │         ┃
    ┃     └───────────┘         ┃    ┃     └───────────┘         ┃    ┃     └───────────┘         ┃
    ┃       │       │           ┃    ┃       │       │           ┃    ┃       │       │           ┃
    ┃    Fail    Success        ┃    ┃    Fail    Success        ┃    ┃    Fail    Success        ┃
    ┃       │       │           ┃    ┃       │       │           ┃    ┃       │       │           ┃
    ┃   ┌───▼───┐   │           ┃    ┃   ┌───▼───┐   │           ┃    ┃   ┌───▼───┐   │           ┃
    ┃   │ Retry │   │           ┃    ┃   │ Retry │   │           ┃    ┃   │ Retry │   │           ┃
    ┃   │  🔄   │───┘           ┃    ┃   │  🔄   │───┘           ┃    ┃   │  🔄   │───┘           ┃
    ┃   └───────┘               ┃    ┃   └───────┘               ┃    ┃   └───────┘               ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                │                                │                                │
                └────────────────────────────────┼────────────────────────────────┘
                                                 │
                                                 ▼
                              ┌─────────────────────────────────────┐
                              │       🔄 POST-EXPLOITATION LOOP     │
                              │  ┌───────────────────────────────┐  │
                              │  │  Planner evaluates:           │  │
                              │  │  • Privilege escalation?      │  │
                              │  │  • Lateral movement?          │  │
                              │  │  • Additional attack vectors? │  │
                              │  └───────────────────────────────┘  │
                              │         │               │           │
                              │     More Tests      Complete        │
                              │         │               │           │
                              │    ┌────▼────┐    ┌────▼────┐       │
                              │    │ 👤 Ask  │    │ 📊 Report│       │
                              │    │ Human   │    │ Generate │       │
                              │    └────┬────┘    └──────────┘       │
                              │         │                            │
                              │    Approved ──▶ Back to Exploitation │
                              └─────────────────────────────────────┘
```

<table>
<tr>
<td width="50%">

**🔄 Never Give Up**
- Each phase retries on failure
- Alternative approaches on dead ends
- Persistent until human says stop

</td>
<td width="50%">

**✅ Human Controls Everything**
- Approval required at every phase
- Full visibility into all operations
- Override and halt at any time

</td>
</tr>
</table>

## 📁 Shared Workspace

Each penetration testing session maintains an isolated workspace for state management, evidence collection, and reporting.

### Directory Structure

```
/workspace/sessions/<session_id>/
├── 📊 state/           # Normalized state (Orchestrator write-only)
│   ├── scope.json              # Target scope definition
│   ├── target_profile.json     # Discovered target information
│   ├── candidates_vuln.json    # Vulnerability candidates
│   ├── candidates_exploit.json # Exploit candidates
│   ├── execution_plans.json    # Approved execution plans
│   ├── findings.json           # Confirmed findings
│   └── state_version.json      # State version tracking
│
├── 📦 evidence/        # Raw data (append-only, sha256 verified)
│   └── <evidence_id>/
│       ├── raw.<ext>           # Raw tool output
│       └── meta.json           # Metadata (timestamp, tool, params)
│
├── 🗄️ cache/           # Query result cache
│   ├── cve/                    # CVE lookup cache
│   ├── snyk/                   # Snyk vulnerability cache
│   └── git/                    # Git repository cache
│
└── 📝 reports/         # Final deliverables
    └── draft.md                # Generated penetration test report
```

### Storage Roles

| Directory | Purpose | Write Policy |
|-----------|---------|--------------|
| `state/` | Tracks current session state, targets, and findings | Orchestrator only |
| `evidence/` | Stores all raw tool outputs with integrity verification | Append-only |
| `cache/` | Caches external API responses (CVE, Snyk) | Read/Write |
| `reports/` | Contains final penetration test reports | Write on completion |

> **Note**: All evidence is stored with SHA-256 hash verification to ensure integrity and reproducibility.

## 📚 Documentation

<details>
<summary><b>Core Documentation</b></summary>

| Document | Contents |
|----------|----------|
| [CLAUDE.md](CLAUDE.md) | System Guidance (Main) |
| [docs/001_shared_workspace.md](docs/001_shared_workspace.md) | Shared Workspace Specification |
| [docs/002_common_schema.md](docs/002_common_schema.md) | Common Schema Definitions |
| [docs/003_passer.md](docs/003_passer.md) | Normalization Engine Specification |
| [docs/004_patch_protocol.md](docs/004_patch_protocol.md) | Patch Protocol Specification |
| [docs/tool_manifest.yaml](docs/tool_manifest.yaml) | Available Tools List |
</details>

<details>
<summary><b>Agent Specifications</b></summary>

| Agent | Specification |
|-------|---------------|
| Orchestrator | [.claude/agents/pentest-orchestrator.md](.claude/agents/pentest-orchestrator.md) |
| Reconnaissance | [.claude/agents/reconnaissance-agent.md](.claude/agents/reconnaissance-agent.md) |
| Enumeration | [.claude/agents/enumeration-agent.md](.claude/agents/enumeration-agent.md) |
| Planner | [.claude/agents/planner-agent.md](.claude/agents/planner-agent.md) |
| Exploitation | [.claude/agents/exploitation-agent.md](.claude/agents/exploitation-agent.md) |
</details>

## 🗺️ Roadmap

- [ ] Web UI Dashboard
- [ ] Multi-target parallel scanning
- [ ] Custom plugin system
- [ ] Report template customization
- [ ] Integration with more MCP servers

## ⚠️ Important Notes

> **Warning**: Use this system only against **authorized targets**

- Conduct all penetration tests with proper authorization
- Indiscriminate scanning, DoS attacks, and data exfiltration are prohibited
- This tool is for **educational and authorized security testing only**

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- 🐛 [Report bugs](https://github.com/cawa102/VibeHackAI/issues)
- 💡 [Request features](https://github.com/cawa102/VibeHackAI/issues)
- 🔀 [Submit PRs](https://github.com/cawa102/VibeHackAI/pulls)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built on [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) by Anthropic
- Inspired by [PentestGPT](https://github.com/GreyDGL/PentestGPT), [Hexstrike](https://github.com/0x4m4/hexstrike-ai)

### MCP Servers

This project integrates with the following open-source MCP servers:

| Server | Repository | Description |
|--------|-----------|-------------|
| **GitHub MCP** | [github/github-mcp-server](https://github.com/github/github-mcp-server) | GitHub's official MCP server |
| **Filesystem MCP** | [@modelcontextprotocol/server-filesystem](https://github.com/modelcontextprotocol/servers) | Anthropic's official filesystem server |
| **Hexstrike MCP** | [github/github-mcp-server](https://github.com/github/github-mcp-server) | 150+ Tools Integration |

We thank all the developers and maintainers of these projects for their contributions to the security community!

---

<div align="center">

**If you find this project useful, please consider giving it a ⭐**

</div>
