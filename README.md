<div align="center">

# VibeHackAI

### AI That Listens. Humans Who Decide.

[![CI](https://github.com/cawa102/VibeHackAI/actions/workflows/ci.yml/badge.svg)](https://github.com/cawa102/VibeHackAI/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Integrated-blueviolet?style=flat-square)](https://modelcontextprotocol.io/)

**Conversational AI pentest system where AI proposes and humans approve.**

[Quick Start](#-quick-start) • [How It Works](#-how-it-works) • [Documentation](docs/) • [Contributing](CONTRIBUTING.md)

</div>

---

## Why VibeHackAI?

Autonomous AI pentest tools have a problem: **they don't know when they're wrong.**

They scan wrong targets, chase rabbit holes, execute dangerous payloads without understanding consequences, and report false positives with full confidence.

VibeHackAI is different. Instead of replacing human judgment, it **augments** it:

- AI analyzes and suggests next steps
- You review in natural language
- You correct when AI strays
- You approve before any dangerous action

---

## Quick Start

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
pip install -e .
pentest-agent
```

```
vibehack> start webapp-assessment

  What targets am I authorized to test?

vibehack> testphp.vulnweb.com

  Scope set. Starting passive reconnaissance...
```

---

## How It Works

```
 AI: Found port 8080 running Apache Struts 2.3.31.
      Vulnerable to CVE-2017-5638 (RCE).
      Should I enumerate the /admin path?

You: Yes, but check /api first - that's the priority.

 AI: Understood. Focusing on /api endpoints.

      [Enumeration complete]

      Confirmed exploitable. I can verify with a safe,
      non-destructive payload.

      This requires your approval.

You: What exactly will the payload do?

 AI: 1. Send crafted Content-Type header
      2. Execute: echo "VIBEHACK_TEST_$(date +%s)"
      3. Check if response contains our string

      No file writes. No persistence. Read-only.

You: Approved.

 AI: [EXECUTING with approval ID: APR-2025-0142]

      Vulnerability CONFIRMED
      Evidence saved: evidence/CVE-2017-5638-verify-001/
      SHA256: a3f2b8c9d4e5f6...
```

**When AI suggests something wrong, you simply tell it.** No restarting. No config edits. Just conversation.

---

## Architecture

```
                         ┌─────────────────────┐
                         │     YOU (Human)     │
                         │  Review • Correct   │
                         │      Approve        │
                         └──────────┬──────────┘
                                    │
                    ╔═══════════════╧═══════════════╗
                    ║        ORCHESTRATOR           ║
                    ║  Conversation • Approval Gate ║
                    ║  Context • Safety Controls    ║
                    ╚═══════════════╤═══════════════╝
                                    │
        ┌───────────┬───────────┬───┴───┬───────────┬───────────┐
        ▼           ▼           ▼       ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │  RECON  │ │  ENUM   │ │ PLANNER │ │ EXPLOIT │ │ REPORT  │
   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
        │           │           │           │           │
        └───────────┴───────────┴─────┬─────┴───────────┘
                                      │
                    ╔═════════════════╧═════════════════╗
                    ║   EVIDENCE STORE (Append-only)    ║
                    ╚═══════════════════════════════════╝
```

**5 Specialized Agents** — Recon, Enumeration, Planner, Exploitation, Reporting

**11+ Tool Integrations** — Nmap, Shodan, Burp Suite, Metasploit, Kali, Snyk, CVE-Search, GitHub, GitLab, and more via [MCP](https://modelcontextprotocol.io/)

**Court-Ready Evidence** — SHA256 hashes, complete audit trails, reproducible attack chains

---

## Safety Controls

| Control | How It Works |
|---------|--------------|
| **Approval Gates** | Dangerous actions (Metasploit, payloads) require explicit approval |
| **Scope Enforcement** | Out-of-scope targets blocked automatically |
| **Course Correction** | Tell AI when it's wrong — it adjusts immediately |
| **Auto-Stop** | Consecutive errors pause execution, await your decision |
| **Rollback** | Failed exploits can roll back to earlier phases |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Full setup guide with MCP configuration |
| [docs/](docs/) | Technical specifications |
| [examples/](examples/) | Tutorials and use cases |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [SECURITY.md](SECURITY.md) | Security policy |

---

## Contributing

```bash
git checkout -b feature/your-feature
pytest
# Submit PR
```

**Wanted:** MCP adapters (Nuclei, SQLMap), i18n, reporting templates, test coverage

---

## Legal

**Authorized security testing only.**

- Use on systems you own or have written permission to test
- Follow responsible disclosure practices
- You are responsible for every action you approve

---

<div align="center">

MIT License • Built on [MCP](https://modelcontextprotocol.io/) by Anthropic • Inspired by [PentestGPT](https://github.com/GreyDGL/PentestGPT)

**[Star this repo](https://github.com/cawa102/VibeHackAI)** if you believe in human-AI collaboration.

</div>
