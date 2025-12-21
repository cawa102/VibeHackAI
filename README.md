<div align="center">

# VibeHackAI

**AI-Assisted Penetration Testing Framework with Human-in-the-Loop Control**

[![CI](https://img.shields.io/github/actions/workflow/status/cawa102/VibeHackAI/ci.yml?style=flat-square&logo=github&label=build)](https://github.com/cawa102/VibeHackAI/actions)
[![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-early_development-orange?style=flat-square)](https://github.com/cawa102/VibeHackAI)

</div>

---

## Overview

VibeHackAI is a conversational penetration testing assistant that combines AI reasoning with mandatory human oversight. Unlike fully autonomous security tools, VibeHackAI requires explicit human approval before executing any potentially dangerous actions.

**Core Philosophy: AI proposes, humans decide.**

The system is designed for security professionals who want AI assistance for reconnaissance, enumeration, and vulnerability analysis while maintaining full control over what actions are taken against target systems.

### Why Human-in-the-Loop?

Fully autonomous penetration testing tools face fundamental limitations:

| Problem | Impact |
|---------|--------|
| Scope violations | AI scans unrelated hosts without understanding authorization boundaries |
| False confidence | AI reports "confirmed" vulnerabilities that don't exist |
| Dangerous actions | AI executes destructive payloads without understanding consequences |
| Context loss | AI forgets previous findings and repeats failed approaches |

VibeHackAI addresses these issues by keeping humans in the decision loop. The AI handles analysis and suggestions; you make the final call on every significant action.

---

## Features

### Implemented (v0.1.0)

- **5 Specialized Agents** — Reconnaissance, Enumeration, Planner, Exploitation, Reporting
- **Approval Gates** — Dangerous operations require explicit human approval
- **Scope Enforcement** — Out-of-scope targets are automatically blocked
- **Evidence Storage** — Append-only storage with SHA256 verification
- **Conversation Interface** — Natural language interaction for course correction
- **Auto-Stop** — Consecutive errors pause execution and await human decision

### Planned (Requires MCP Integration)

- External tool integration (Nmap, Shodan, Metasploit, Burp Suite, Snyk)
- Real-time vulnerability scanning
- Automated evidence collection from live systems

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Installation

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Launch

```bash
pentest-agent
```

---

## Usage (Demo Mode)

The current release runs in **demo mode** with simulated responses. This allows you to explore the interface and workflow without connecting to external tools or scanning real targets.

### Demo Mode Characteristics

| Aspect | Behavior |
|--------|----------|
| **Network activity** | None — all responses are simulated |
| **External APIs** | Not called — no API keys required |
| **Target systems** | Not contacted — safe to run anywhere |
| **Data persistence** | Local only — session data stored in `./workspace/` |

### Basic Commands

After launching `pentest-agent`, you can use the following commands:

| Command | Description |
|---------|-------------|
| `help` | Display available commands and usage |
| `start <session-name>` | Create a new pentest session |
| `scope set <target>` | Define authorized target scope |
| `status` | Show current session and phase status |
| `approve` / `deny` | Respond to approval requests |
| `stop` | Pause current operation |
| `exit` | End session and exit |

### Example Session

```
$ pentest-agent

[*] VibeHackAI v0.1.0 initialized
[*] Type 'help' for available commands

vibehack> start demo-session

[*] Session created: demo-session
[?] What targets are you authorized to test?

vibehack> scope set 192.168.1.0/24

[*] Scope configured: 192.168.1.0/24
[*] Starting reconnaissance phase...

vibehack> status

Session: demo-session
Phase: RECON
Scope: 192.168.1.0/24
Findings: 0
Pending approvals: 0
```

### Expected Behavior

When functioning correctly, you should see:

- `[*]` prefix for informational messages
- `[?]` prefix for questions requiring input
- `[!]` prefix for approval requests
- `[✓]` prefix for completed actions
- Clear indication of current phase (RECON → ENUM → PLAN → EXPLOIT → REPORT)

### Demo vs. Claude Code Mode

| Capability | Demo Mode | With Claude Code |
|------------|-----------|------------------|
| Interface exploration | ✓ | ✓ |
| Workflow validation | ✓ | ✓ |
| Simulated findings | ✓ | Real findings |
| AI reasoning & analysis | — | ✓ (Claude provides intelligence) |
| Network scanning | — | ✓ (Nmap, Shodan) |
| Vulnerability lookup | — | ✓ (Snyk, CVE databases) |
| Active exploitation | — | ✓ (Metasploit, with approval) |
| Report generation | — | ✓ (AI-generated reports) |

---

## Usage with Claude Code (Recommended)

For full AI-powered penetration testing, use VibeHackAI with [Claude Code](https://claude.ai/code). Claude Code provides the AI reasoning that analyzes findings, plans attack strategies, and generates comprehensive reports.

### Why Claude Code?

VibeHackAI's Python codebase provides the **structure and workflow**, while Claude Code provides the **AI intelligence**:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Claude Code   │───▶│   VibeHackAI    │───▶│   MCP Servers   │
│   (AI Brain)    │    │   (Framework)   │    │   (Tools)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │
        ├── Analyzes scan results
        ├── Identifies vulnerabilities
        ├── Plans attack strategies
        ├── Requests human approval
        └── Generates reports
```

### Prerequisites

- [Claude Code](https://claude.ai/code) subscription
- Node.js 18+ (for MCP servers)
- Docker (optional, for GitHub MCP)
- API keys for external services

### Step 1: Clone and Install

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
```

### Step 2: Configure MCP Servers

Copy `.mcp.json` to your Claude Code configuration directory and update the API keys:

**Required API Keys:**

| Service | Get API Key | Purpose |
|---------|-------------|---------|
| Shodan | [account.shodan.io](https://account.shodan.io/) | Passive reconnaissance |
| Snyk | [app.snyk.io/account](https://app.snyk.io/account) | Vulnerability database |
| GitHub | [github.com/settings/tokens](https://github.com/settings/tokens) | Repository analysis |

**Minimal `.mcp.json` configuration:**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/workspace"]
    },
    "nmap": {
      "command": "npx",
      "args": ["-y", "mcp-nmap-server"]
    },
    "shodan": {
      "command": "npx",
      "args": ["-y", "@burtthecoder/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

See `.mcp.json` in this repository for full configuration including Metasploit, Burp Suite, and other tools.

### Step 3: Start Penetration Test

Open Claude Code in the VibeHackAI directory and provide your target:

```
I have written authorization to test 192.168.1.0/24.
Please perform a penetration test following the VibeHackAI workflow:
1. Reconnaissance - gather information about the target
2. Enumeration - identify services and entry points
3. Vulnerability analysis - map CVEs and potential exploits
4. Exploitation - test vulnerabilities (with my approval)
5. Report - generate findings report
```

Claude will:
- Read the project structure and understand the workflow
- Use MCP tools (Nmap, Shodan, etc.) for scanning
- Analyze results and identify vulnerabilities
- Ask for your approval before any exploitation
- Generate a comprehensive penetration test report

### Example Session

```
You: Test 10.0.0.5 for vulnerabilities. I have authorization.

Claude: I'll start reconnaissance on 10.0.0.5.

[Uses Shodan MCP to query host information]
[Uses Nmap MCP to scan ports]

Found:
- Port 22: OpenSSH 7.4
- Port 80: Apache 2.4.6
- Port 443: Apache with outdated SSL

I've identified potential vulnerabilities:
1. CVE-2021-41617 in OpenSSH 7.4 (Medium)
2. CVE-2019-0211 in Apache 2.4.6 (High)

Would you like me to:
a) Search for exploits for these CVEs?
b) Continue enumeration on web services?
c) Generate a preliminary report?

You: Search for exploits, but ask before running anything.

Claude: [Searches CVE databases]
[Finds Metasploit module for Apache vulnerability]

⚠️ APPROVAL REQUEST:
I found exploit/multi/http/apache_mod_cgi_bash_env_exec
Target: 10.0.0.5:80
Risk: May cause service disruption

Do you approve this exploitation attempt? (yes/no)
```

---

## Scope & Safety

### Authorization Requirements

**VibeHackAI must only be used against systems you are explicitly authorized to test.**

Before using this tool:

1. Obtain written authorization from the system owner
2. Define clear scope boundaries (IP ranges, domains, excluded systems)
3. Understand and comply with applicable laws and regulations

### Prohibited Actions

The following are strictly prohibited:

- Scanning or testing systems without explicit written authorization
- Indiscriminate scanning of public IP ranges
- Using the tool for denial-of-service attacks
- Data exfiltration beyond proof-of-concept
- Establishing persistence on target systems
- Lateral movement without explicit approval per hop

### Destructive Action Controls

| Control | Status | Description |
|---------|--------|-------------|
| Approval gates | Implemented | All exploitation actions require explicit approval |
| Scope lock | Implemented | Out-of-scope targets blocked automatically |
| Dry-run mode | Implemented | Preview commands before execution |
| Rollback | Implemented | Revert to previous phase on failure |
| Destructive payload block | Planned | Block payloads that modify target filesystem |
| Rate limiting | Planned | Prevent accidental DoS through request flooding |

### Project Philosophy

VibeHackAI is intentionally **not** a fully autonomous attack tool. We believe:

1. **Humans must remain accountable** — Security testing carries legal and ethical responsibilities that cannot be delegated to AI
2. **Context matters** — AI cannot fully understand authorization boundaries, business impact, or engagement rules
3. **Errors require judgment** — When something goes wrong, human expertise is needed to decide next steps
4. **Trust must be earned** — Each action builds (or breaks) trust with the target organization

The human-in-the-loop design is a feature, not a limitation.

---

## Architecture

```
                    ┌─────────────────────────┐
                    │      Human Operator     │
                    │  Review → Correct →     │
                    │       Approve           │
                    └───────────┬─────────────┘
                                │
                    ╔═══════════╧═══════════╗
                    ║     Orchestrator      ║
                    ║  Routing │ Approval   ║
                    ║  State   │ Safety     ║
                    ╚═══════════╤═══════════╝
                                │
        ┌───────┬───────┬───────┼───────┬───────┐
        ▼       ▼       ▼       ▼       ▼       ▼
    ┌───────┐┌───────┐┌───────┐┌───────┐┌───────┐
    │ Recon ││ Enum  ││Planner││Exploit││Report │
    └───┬───┘└───┬───┘└───┬───┘└───┬───┘└───┬───┘
        └────────┴────────┴───┬────┴────────┘
                              │
                    ╔═════════╧═════════╗
                    ║  Evidence Store   ║
                    ║ Append-only │ SHA256
                    ╚═══════════════════╝
```

### Components

| Component | Responsibility |
|-----------|---------------|
| **Orchestrator** | Coordinates agents, enforces approvals, manages state |
| **Recon Agent** | Passive information gathering (OSINT, DNS, Shodan) |
| **Enum Agent** | Active enumeration (ports, services, endpoints) |
| **Planner Agent** | CVE mapping, exploit selection, attack planning |
| **Exploit Agent** | Controlled exploitation with approval gates |
| **Report Agent** | Finding consolidation and report generation |
| **Evidence Store** | Immutable storage with cryptographic verification |

---

## Roadmap

### Current Release (v0.1.0)

- [x] Core architecture (Orchestrator, Agents, Schemas)
- [x] CLI interface with conversation support
- [x] Safety controls (approval gates, scope lock, auto-stop)
- [x] Demo mode with simulated responses
- [x] Evidence storage framework

### Next Milestone (v0.2.0)

- [ ] MCP adapter integration
- [ ] Nmap MCP support
- [ ] Basic Shodan integration
- [ ] Session persistence and resume

### Future

- [ ] Metasploit MCP integration
- [ ] Burp Suite MCP integration
- [ ] Report generation (PDF, Markdown)
- [ ] Multi-session management

---

## Documentation

| Resource | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Full setup guide including MCP configuration |
| [docs/](docs/) | Technical specifications and design documents |
| [examples/](examples/) | Usage examples and tutorials |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

```bash
git checkout -b feature/your-feature
pytest  # Ensure tests pass
# Submit pull request
```

### Areas of Interest

- MCP adapter implementations
- Test coverage improvements
- Documentation and examples
- Internationalization

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built on [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) by Anthropic
- Inspired by [PentestGPT](https://github.com/GreyDGL/PentestGPT)

---

<div align="center">

**⚠️ Use responsibly. You are accountable for every action you approve.**

</div>
