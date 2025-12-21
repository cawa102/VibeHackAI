<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:16213e,100:0f3460&height=200&section=header&text=VibeHackAI&fontSize=80&fontColor=e94560&fontAlignY=35&desc=AI%20That%20Listens.%20Humans%20Who%20Decide.&descSize=20&descAlignY=55&descAlign=50" width="100%"/>

[![CI](https://img.shields.io/github/actions/workflow/status/cawa102/VibeHackAI/ci.yml?style=for-the-badge&logo=github&label=CI)](https://github.com/cawa102/VibeHackAI/actions)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-Integrated-blueviolet?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggOHoiLz48L3N2Zz4=)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<br>

**Conversational AI pentest system where AI proposes and humans approve.**

<br>

[<kbd> <br> Quick Start <br> </kbd>](#-quick-start)&nbsp;&nbsp;
[<kbd> <br> How It Works <br> </kbd>](#-how-it-works)&nbsp;&nbsp;
[<kbd> <br> Documentation <br> </kbd>](docs/)&nbsp;&nbsp;
[<kbd> <br> Contributing <br> </kbd>](CONTRIBUTING.md)

</div>

<br>

## The Problem

> Autonomous AI pentest tools don't know when they're wrong.

They scan wrong targets. Chase rabbit holes. Execute dangerous payloads without understanding consequences. Report false positives with full confidence.

**VibeHackAI is different.** AI proposes. You review. You correct. You approve.

<br>

## Quick Start

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI && pip install -e . && pentest-agent
```

<br>

## How It Works

<table>
<tr>
<td>

```
┌────────────────────────────────────────┐
│  $ vibehack                            │
├────────────────────────────────────────┤
│                                        │
│  🤖 Found Apache Struts 2.3.31         │
│     on 192.168.1.50:8080               │
│                                        │
│     Vulnerable to CVE-2017-5638        │
│     Should I enumerate /admin?         │
│                                        │
│  ▌                                     │
└────────────────────────────────────────┘
```

</td>
<td>

```
┌────────────────────────────────────────┐
│  $ vibehack                            │
├────────────────────────────────────────┤
│                                        │
│  👤 Check /api first, that's priority  │
│                                        │
│  🤖 Understood. Focusing on /api.      │
│                                        │
│     [Confirmed exploitable]            │
│                                        │
│     ⚠️  Requires your approval         │
│                                        │
└────────────────────────────────────────┘
```

</td>
</tr>
<tr>
<td>

```
┌────────────────────────────────────────┐
│  $ vibehack                            │
├────────────────────────────────────────┤
│                                        │
│  👤 What will the payload do?          │
│                                        │
│  🤖 1. Send crafted header             │
│     2. Execute: echo "TEST_$(date)"    │
│     3. Check response                  │
│                                        │
│     No writes. No persistence.         │
│     Read-only verification.            │
│                                        │
└────────────────────────────────────────┘
```

</td>
<td>

```
┌────────────────────────────────────────┐
│  $ vibehack                            │
├────────────────────────────────────────┤
│                                        │
│  👤 Approved.                          │
│                                        │
│  🤖 [EXECUTING: APR-2025-0142]         │
│                                        │
│     ✅ Vulnerability CONFIRMED         │
│                                        │
│     Evidence: evidence/CVE-2017-5638/  │
│     SHA256: a3f2b8c9d4e5f6...          │
│                                        │
└────────────────────────────────────────┘
```

</td>
</tr>
</table>

<p align="center"><b>When AI is wrong, you simply tell it. No restart. No config. Just conversation.</b></p>

<br>

## Architecture

```
                    ╭──────────────────────────────────────╮
                    │            👤 YOU                    │
                    │      Review · Correct · Approve      │
                    ╰──────────────────┬───────────────────╯
                                       │
                    ╔══════════════════╧══════════════════╗
                    ║          ORCHESTRATOR               ║
                    ║   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐   ║
                    ║   │ 💬  │ │ 🔒  │ │ 🧠  │ │ ⛔  │   ║
                    ║   │Talk │ │Gate │ │State│ │Stop │   ║
                    ║   └─────┘ └─────┘ └─────┘ └─────┘   ║
                    ╚══════════════════╤══════════════════╝
                                       │
          ┌────────────┬───────────┬───┴───┬────────────┬────────────┐
          ▼            ▼           ▼       ▼            ▼            ▼
     ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
     │  🔍     │  │  🎯     │  │  📋     │  │  💥     │  │  📄     │
     │  Recon  │  │  Enum   │  │ Planner │  │ Exploit │  │ Report  │
     └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘
          │            │           │            │            │
          └────────────┴───────────┴─────┬──────┴────────────┘
                                         │
                    ╔════════════════════╧════════════════════╗
                    ║       🗄️  EVIDENCE STORE                ║
                    ║       Append-only · SHA256 · Audit      ║
                    ╚═════════════════════════════════════════╝
```

<br>

<table>
<tr>
<td align="center" width="33%">

### 🤖 5 Agents

Recon · Enum · Planner<br>
Exploit · Report

</td>
<td align="center" width="33%">

### 🔌 11+ Tools

Nmap · Shodan · Burp<br>
Metasploit · Kali · Snyk

</td>
<td align="center" width="33%">

### 🔐 Evidence

SHA256 verified<br>
Court-ready audit trail

</td>
</tr>
</table>

<br>

## Safety

| | Control | Description |
|:--:|---------|-------------|
| 🚦 | **Approval Gates** | Dangerous actions require explicit approval |
| 🎯 | **Scope Lock** | Out-of-scope targets blocked automatically |
| 💬 | **Course Correct** | Tell AI when it's wrong — instant adjustment |
| ⛔ | **Auto-Stop** | Consecutive errors pause for your decision |
| ↩️ | **Rollback** | Failed exploits roll back to earlier phases |

<br>

## Documentation

| | Resource | Description |
|:--:|----------|-------------|
| 📦 | [INSTALLATION.md](INSTALLATION.md) | Setup guide with MCP config |
| 📚 | [docs/](docs/) | Technical specifications |
| 🎓 | [examples/](examples/) | Tutorials and use cases |
| 🤝 | [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| 🔒 | [SECURITY.md](SECURITY.md) | Security policy |

<br>

## Contributing

```bash
git checkout -b feature/your-feature && pytest
```

**Wanted:** MCP adapters · i18n · Report templates · Test coverage

<br>

## Legal

**Authorized security testing only.** You are responsible for every action you approve.

<br>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:16213e,100:0f3460&height=100&section=footer" width="100%"/>

MIT License · Built on [MCP](https://modelcontextprotocol.io/) · Inspired by [PentestGPT](https://github.com/GreyDGL/PentestGPT)

<br>

[![Star](https://img.shields.io/github/stars/cawa102/VibeHackAI?style=social)](https://github.com/cawa102/VibeHackAI)

</div>
