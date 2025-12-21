<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:000000,100:0a0a0a&height=1&section=header" width="100%"/>

```

   ██╗   ██╗██╗██████╗ ███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗ █████╗ ██╗
   ██║   ██║██║██╔══██╗██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║
   ██║   ██║██║██████╔╝█████╗  ███████║███████║██║     █████╔╝ ███████║██║
   ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══██║██║
    ╚████╔╝ ██║██████╔╝███████╗██║  ██║██║  ██║╚██████╗██║  ██╗██║  ██║██║
     ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝

   ┌──────────────────────────────────────────────────────────────────────┐
   │  [■] AI-POWERED PENTEST SYSTEM          [HUMAN-IN-THE-LOOP ENABLED] │
   │  ════════════════════════════════════════════════════════════════   │
   │  STATUS: OPERATIONAL    MODE: COLLABORATIVE    SAFETY: ENFORCED     │
   └──────────────────────────────────────────────────────────────────────┘

```

<br>

[![CI](https://img.shields.io/github/actions/workflow/status/cawa102/VibeHackAI/ci.yml?style=flat-square&logo=github&logoColor=white&label=BUILD&labelColor=000000&color=00ff00)](https://github.com/cawa102/VibeHackAI/actions)
[![Python](https://img.shields.io/badge/PYTHON-3.10+-00ff00?style=flat-square&logo=python&logoColor=00ff00&labelColor=000000)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-INTEGRATED-00ffff?style=flat-square&labelColor=000000)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/LICENSE-MIT-00ff00?style=flat-square&labelColor=000000)](LICENSE)

<br>

```
 ╔═══════════════════════════════════════════════════════════════════════════╗
 ║                    AI THAT LISTENS. HUMANS WHO DECIDE.                    ║
 ╚═══════════════════════════════════════════════════════════════════════════╝
```

[<kbd>⚡ QUICK START</kbd>](#-quick-start)&nbsp;&nbsp;
[<kbd>🔧 HOW IT WORKS</kbd>](#-how-it-works)&nbsp;&nbsp;
[<kbd>📁 DOCS</kbd>](docs/)&nbsp;&nbsp;
[<kbd>🤝 CONTRIBUTE</kbd>](CONTRIBUTING.md)

</div>

<br>

---

## ⚠️ The Problem

```
[!] CRITICAL: Autonomous AI pentest tools don't know when they're wrong.

    → Wrong targets scanned
    → Rabbit holes pursued
    → Dangerous payloads executed without understanding
    → False positives reported with full confidence
```

**VibeHackAI is different.** `AI proposes` → `You review` → `You correct` → `You approve`

---

## ⚡ Quick Start

```bash
$ git clone https://github.com/cawa102/VibeHackAI.git
$ cd VibeHackAI && pip install -e . && pentest-agent

[*] VibeHackAI v0.1.0 initialized
[*] Awaiting target scope...
```

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ vibehack> scan 192.168.1.0/24                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [*] RECON COMPLETE                                                         │
│                                                                             │
│      Found: Apache Struts 2.3.31 @ 192.168.1.50:8080                        │
│      CVE:   CVE-2017-5638 (RCE) - CRITICAL                                  │
│                                                                             │
│  [?] Enumerate /admin path? [Y/n]                                           │
│                                                                             │
│  vibehack> focus on /api first                                              │
│                                                                             │
│  [*] REDIRECTING: /api endpoints prioritized                                │
│  [*] ENUMERATION COMPLETE                                                   │
│                                                                             │
│      Endpoint: /api/v1/users - SQLi potential                               │
│      Endpoint: /api/v1/upload - Unrestricted file upload                    │
│                                                                             │
│  [!] APPROVAL REQUIRED                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  ACTION:  Verify CVE-2017-5638 exploitability                       │    │
│  │  METHOD:  Non-destructive payload (echo test)                       │    │
│  │  RISK:    LOW - Read-only verification                              │    │
│  │                                                                     │    │
│  │  [A]pprove  [D]eny  [?]Explain                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  vibehack> A                                                                │
│                                                                             │
│  [✓] EXECUTING: APR-2025-0142                                               │
│  [✓] VULNERABILITY CONFIRMED                                                │
│  [✓] EVIDENCE SAVED: evidence/CVE-2017-5638/                                │
│  [✓] SHA256: a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**`When AI is wrong, you tell it. No restart. No config. Just conversation.`**

---

## 🏗️ Architecture

```
                         ┌─────────────────────────────┐
                         │         👤 OPERATOR         │
                         │   REVIEW ─ CORRECT ─ APPROVE│
                         └──────────────┬──────────────┘
                                        │
                    ╔═══════════════════╧═══════════════════╗
                    ║            ORCHESTRATOR               ║
                    ║  ┌──────┬──────┬──────┬──────┐       ║
                    ║  │ CONV │ GATE │ STATE│ STOP │       ║
                    ║  │  💬  │  🔒  │  🧠  │  ⛔  │       ║
                    ║  └──────┴──────┴──────┴──────┘       ║
                    ╚═══════════════════╤═══════════════════╝
                                        │
       ┌──────────┬──────────┬──────────┼──────────┬──────────┐
       ▼          ▼          ▼          ▼          ▼          ▼
   ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐
   │ RECON │  │ ENUM  │  │ PLAN  │  │EXPLOIT│  │REPORT │
   │  🔍   │  │  🎯   │  │  📋   │  │  💥   │  │  📄   │
   └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘
       └──────────┴──────────┴──────────┴──────────┘
                             │
                ╔════════════╧════════════╗
                ║    🗄️ EVIDENCE STORE    ║
                ║  APPEND-ONLY │ SHA256   ║
                ╚═════════════════════════╝
```

<table>
<tr>
<td align="center">

**`5 AGENTS`**<br>
<sub>Recon • Enum • Planner • Exploit • Report</sub>

</td>
<td align="center">

**`11+ TOOLS`**<br>
<sub>Nmap • Shodan • Burp • Metasploit • Kali • Snyk</sub>

</td>
<td align="center">

**`EVIDENCE`**<br>
<sub>SHA256 Verified • Court-Ready Audit</sub>

</td>
</tr>
</table>

---

## 🛡️ Safety Controls

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CONTROL           │  STATUS   │  DESCRIPTION                           │
├──────────────────────────────────────────────────────────────────────────┤
│  Approval Gates    │  [ON]     │  Dangerous actions require approval    │
│  Scope Lock        │  [ON]     │  Out-of-scope targets auto-blocked     │
│  Course Correct    │  [ON]     │  Natural language redirection          │
│  Auto-Stop         │  [ON]     │  Consecutive errors pause execution    │
│  Rollback          │  [ON]     │  Failed exploits revert to safe state  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Documentation

| | Resource | Description |
|:--|:---------|:------------|
| `📦` | [INSTALLATION.md](INSTALLATION.md) | Setup guide + MCP config |
| `📁` | [docs/](docs/) | Technical specifications |
| `🎓` | [examples/](examples/) | Tutorials |
| `🤝` | [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guide |
| `🔒` | [SECURITY.md](SECURITY.md) | Security policy |

---

## 🤝 Contributing

```bash
$ git checkout -b feature/your-feature
$ pytest
$ # Submit PR
```

**`WANTED:`** MCP adapters • i18n • Report templates • Test coverage

---

## ⚖️ Legal

```
[!] AUTHORIZED SECURITY TESTING ONLY
    You are responsible for every action you approve.
```

---

<div align="center">

```
───────────────────────────────────────────────────────────────────────────────
  MIT License │ Built on MCP │ Inspired by PentestGPT
───────────────────────────────────────────────────────────────────────────────
```

[![Star](https://img.shields.io/github/stars/cawa102/VibeHackAI?style=flat-square&logo=github&label=STARS&labelColor=000000&color=00ff00)](https://github.com/cawa102/VibeHackAI)
[![Forks](https://img.shields.io/github/forks/cawa102/VibeHackAI?style=flat-square&logo=github&label=FORKS&labelColor=000000&color=00ffff)](https://github.com/cawa102/VibeHackAI/fork)

</div>
