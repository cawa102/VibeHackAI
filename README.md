<div align="center">

```
 ██╗   ██╗██╗██████╗ ███████╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗     █████╗ ██╗
 ██║   ██║██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗██║
 ██║   ██║██║██████╔╝█████╗      ███████║███████║██║     █████╔╝     ███████║██║
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝      ██╔══██║██╔══██║██║     ██╔═██╗     ██╔══██║██║
  ╚████╔╝ ██║██████╔╝███████╗    ██║  ██║██║  ██║╚██████╗██║  ██╗    ██║  ██║██║
   ╚═══╝  ╚═╝╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
```

# AI That Listens. Humans Who Decide.

### Conversational AI Pentest System with Human-in-the-Loop Control

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Integrated-blueviolet?style=for-the-badge)](https://modelcontextprotocol.io/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)

<br>

**VibeHackAI** is not another "autonomous" AI pentest tool.<br>
It's a **collaborative system** where AI proposes and humans approve — through natural conversation.

[Getting Started](#-quick-start) •
[The Problem We Solve](#-the-problem-ai-that-goes-rogue) •
[How It Works](#-how-we-solve-it-conversation-not-automation) •
[Contributing](CONTRIBUTING.md)

<br>

---

</div>

## 🚨 The Problem: AI That Goes Rogue

The rise of AI in penetration testing brought a critical issue:

<div align="center">

### **Autonomous AI agents don't know when they're wrong.**

</div>

| Issue | What Happens |
|-------|--------------|
| **Wrong Target** | AI scans unrelated hosts, causing scope violations |
| **Rabbit Holes** | AI wastes hours on low-value findings while missing critical vulns |
| **Dangerous Actions** | AI executes destructive payloads without understanding consequences |
| **False Confidence** | AI reports "confirmed" vulnerabilities that don't actually exist |
| **Context Loss** | AI forgets previous findings, repeating failed approaches |

**Traditional AI pentest tools treat humans as observers.** You watch the AI run, hoping it makes the right choices. When it doesn't, you start over.

This is not AI-assisted pentesting. This is **AI gambling**.

## 💡 How We Solve It: Conversation, Not Automation

VibeHackAI flips the paradigm:

<div align="center">

### **AI proposes. You guide. Together, you succeed.**

</div>

Instead of autonomous execution, VibeHackAI creates a **conversational workflow** where:

1. **AI analyzes** the target and suggests next steps
2. **You review** the suggestions in natural language
3. **You correct** if AI is heading in the wrong direction
4. **AI learns** from your feedback and adjusts
5. **You approve** before any dangerous action executes

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        REAL CONVERSATION EXAMPLE                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

🤖 AI: I've completed reconnaissance on 192.168.1.0/24.
       Found 23 hosts, 147 open ports.

       I noticed port 8080 on 192.168.1.50 running Apache Struts 2.3.31.
       This version is vulnerable to CVE-2017-5638 (S2-045, RCE).

       Recommended next step: Enumerate the Struts endpoint to confirm
       the vulnerability before attempting exploitation.

       Should I proceed with enumeration?

👤 You: Yes, but focus on the /admin path first - that's the priority target.

🤖 AI: Understood. Focusing enumeration on /admin path.

       [Enumeration complete]

       Confirmed: /admin/struts2-showcase/ is accessible.
       The application appears to be a demo instance.

       I can attempt a safe verification of CVE-2017-5638 using a
       non-destructive payload. This will confirm exploitability
       without causing any changes to the target.

       ⚠️  This requires your approval as it involves active exploitation.

👤 You: What exactly will the verification payload do?

🤖 AI: The verification payload will:
       1. Send a crafted Content-Type header
       2. Execute: `echo "VIBEHACK_TEST_$(date +%s)"`
       3. Check if the response contains our unique string

       This only reads output - no file writes, no persistence,
       no lateral movement. The command is deterministic and safe.

       Risk Level: LOW (read-only verification)
       Reversibility: N/A (no changes made)

👤 You: Approved. Proceed.

🤖 AI: [EXECUTING with approval ID: APR-2025-0142]

       ✅ Vulnerability CONFIRMED

       Response contained: "VIBEHACK_TEST_1737456789"
       Execution time: 0.3s

       Evidence saved: evidence/CVE-2017-5638-verify-001/
       - Request/Response captured
       - SHA256: a3f2b8c9d4e5f6...

       Finding created: FIND-001 (Critical)

       Next recommended action: Document finding and move to next target,
       or attempt deeper exploitation with data exfiltration proof.

       What would you like to do?

👤 You: Document this finding. Let's move to the Redis instance you found earlier.

🤖 AI: Finding documented. Moving to 192.168.1.72:6379 (Redis 4.0.9)...
```

**This is the difference.** When AI suggests something wrong, you simply tell it. No restarting. No config file edits. Just conversation.

## 🏗️ Architecture: Humans at the Center

<div align="center">

```
                              ┌─────────────────────┐
                              │    👤 YOU (Human)   │
                              │                     │
                              │  • Review findings  │
                              │  • Correct course   │
                              │  • Approve actions  │
                              └──────────┬──────────┘
                                         │
                          ┌──────────────┼──────────────┐
                          │     Conversation Layer      │
                          │  (Natural Language I/O)     │
                          └──────────────┬──────────────┘
                                         │
                    ╔════════════════════╧════════════════════╗
                    ║           🎯 ORCHESTRATOR               ║
                    ║                                         ║
                    ║  • Interprets your guidance             ║
                    ║  • Coordinates agent actions            ║
                    ║  • Enforces approval gates              ║
                    ║  • Maintains context across phases      ║
                    ╚════════════════════╤════════════════════╝
                                         │
           ┌─────────────┬───────────────┼───────────────┬─────────────┐
           ▼             ▼               ▼               ▼             ▼
    ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
    │    🔍      │ │    🎯      │ │    📋      │ │    💥      │ │    📄      │
    │   RECON    │ │   ENUM     │ │  PLANNER   │ │  EXPLOIT   │ │  REPORTER  │
    │   Agent    │ │   Agent    │ │   Agent    │ │   Agent    │ │   Agent    │
    └────────────┘ └────────────┘ └────────────┘ └────────────┘ └────────────┘
           │             │               │               │             │
           └─────────────┴───────────────┴───────────────┴─────────────┘
                                         │
                    ╔════════════════════╧════════════════════╗
                    ║     🔐 EVIDENCE STORE                   ║
                    ║  Append-only • SHA256 • Audit Trail     ║
                    ╚═════════════════════════════════════════╝
```

</div>

## 🛡️ Safety Through Conversation

VibeHackAI implements **multi-layer safety** — and every layer involves you:

### 1. Approval Gates (You Decide What Executes)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚠️  APPROVAL REQUIRED                                              │
│                                                                     │
│  Action:   Metasploit module execution                              │
│  Module:   exploit/multi/http/struts2_rest_xstream                  │
│  Target:   192.168.1.50:8080                                        │
│  Payload:  cmd/unix/reverse_bash                                    │
│                                                                     │
│  Risk Assessment:                                                   │
│  ├─ Scope:        ✅ Within authorized range                        │
│  ├─ Reversibility: ⚠️ Creates process on target                     │
│  ├─ Detection:    🔴 Likely to trigger IDS                          │
│  └─ Impact:       🔴 Full system compromise if successful           │
│                                                                     │
│  AI Recommendation: Proceed - high confidence in exploitability     │
│                                                                     │
│  Your options:                                                      │
│  [A] Approve    [M] Modify parameters    [D] Deny    [?] Explain   │
└─────────────────────────────────────────────────────────────────────┘
```

### 2. Course Correction (You Guide When AI Strays)

```
🤖 AI: Based on enumeration, I recommend focusing on the MySQL database
       on port 3306. I'll attempt default credential testing.

👤 You: No, the client specifically said MySQL is out of scope.
        Focus on web application vulnerabilities only.

🤖 AI: Understood. Removing MySQL from scope.

       Refocusing on web application attack surface:
       - 3 forms with potential SQLi vectors
       - 1 file upload endpoint
       - 2 API endpoints with improper input validation

       Should I start with the file upload vulnerability?
       It has the highest potential impact.

👤 You: Yes, that's the right priority.
```

### 3. Rollback When Things Go Wrong

```
🤖 AI: Exploitation attempt failed.

       Error: Target appears to be running a patched version.
       CVE-2017-5638 payload did not execute.

       I have two options:
       1. Try alternative payload encoding
       2. Roll back and investigate version more thoroughly

       Given the failure, I recommend option 2 - we may have
       misidentified the Struts version during enumeration.

       Should I roll back to enumeration phase?

👤 You: Yes, let's verify the version first.

🤖 AI: Rolling back to enumeration.
       Previous exploitation attempt logged in evidence.
       No changes were made to target system.
```

### 4. Automatic Stop Conditions

```
⛔ AUTOMATIC STOP TRIGGERED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Reason: Consecutive similar errors detected (3x timeout on same host)

This may indicate:
• Target is blocking our requests
• Network issue
• Incorrect target configuration

All agents paused. No further actions will be taken.

Awaiting your decision:
[R] Resume with different approach
[S] Skip this target
[A] Abort session
[I] Investigate logs
```

## ✨ Key Features

<table>
<tr>
<td width="50%">

### 🤖 4 Specialized AI Agents

Each agent is an expert in its domain:

- **Reconnaissance** — OSINT, DNS, Shodan, passive intel
- **Enumeration** — Services, endpoints, attack surface
- **Planner** — CVE mapping, exploit selection, strategy
- **Exploitation** — Controlled attacks with your approval

</td>
<td width="50%">

### 🔌 11+ Security Tool Integrations

One interface, all your tools (via MCP):

```
Nmap        Shodan       OSINT
Burp Suite  Metasploit   Kali Linux
Snyk        CVE-Search   GitHub
GitLab      Filesystem   + more
```

</td>
</tr>
<tr>
<td width="50%">

### 💬 Natural Language Control

No complex commands. Just tell the AI what you want:

```
"Skip port 22, it's a honeypot"
"Focus on the API endpoints"
"That's a false positive, ignore it"
"Explain why you chose this exploit"
```

</td>
<td width="50%">

### 📋 Court-Ready Evidence

Every finding backed by proof:

- **Append-only** evidence storage
- **SHA256** hash verification
- **Complete** audit trails
- **Reproducible** attack chains

</td>
</tr>
</table>

## 🚀 Quick Start

### 30-Second Install

```bash
# Clone
git clone https://github.com/cawa102/VibeHackAI.git && cd VibeHackAI

# Install
pip install -e .

# Run
pentest-agent
```

### Your First Session

```bash
$ pentest-agent

╔══════════════════════════════════════════════════════════════════╗
║                       🎯 VibeHackAI v0.1.0                        ║
║          Conversational AI Penetration Testing Assistant          ║
╚══════════════════════════════════════════════════════════════════╝

🤖 Welcome! I'm your AI pentest assistant.

   Unlike autonomous tools, I work WITH you - proposing actions,
   explaining my reasoning, and waiting for your guidance.

   What would you like to do?

   • "start <session-name>" - Begin a new pentest session
   • "resume <session-id>" - Continue a previous session
   • "help" - Learn about available commands

vibehack> start webapp-assessment

🤖 Session created: webapp-assessment

   Before we begin, I need to understand the scope.
   What targets am I authorized to test?

vibehack> The target is testphp.vulnweb.com - it's a legal test site

🤖 Understood. I've set the scope to:
   • testphp.vulnweb.com (and subdomains)

   I'll now begin reconnaissance. I'll report my findings
   and wait for your direction before taking any active steps.

   Starting passive reconnaissance...
```

## 📊 How It Compares

| Aspect | Traditional AI Pentest | VibeHackAI |
|--------|----------------------|------------|
| **Control Model** | Autonomous (AI decides) | Collaborative (Human + AI) |
| **Error Handling** | Retry until timeout | Ask human for guidance |
| **Scope Violations** | May occur silently | Blocked with explanation |
| **Course Correction** | Restart required | Natural conversation |
| **Transparency** | Black box | Full reasoning exposed |
| **Learning** | Pre-trained only | Adapts to your feedback |

## 📁 Project Structure

```
VibeHackAI/
├── 🤖 src/
│   ├── agents/           # The 4 specialized AI agents
│   ├── orchestrator/     # Coordination, approval, safety systems
│   ├── cli/              # Conversational interface
│   ├── storage/          # State & evidence management
│   ├── mcp_adapters/     # Tool integrations (11+)
│   ├── passer/           # Data normalization
│   └── schemas/          # Type definitions
├── 📚 docs/              # Specifications (source of truth)
├── 🧪 tests/             # Comprehensive test suite
└── 💡 examples/          # Usage examples & tutorials
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Complete setup guide with MCP configuration |
| [examples/](examples/) | Hands-on tutorials and use cases |
| [docs/](docs/) | Technical specifications (9 detailed docs) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [SECURITY.md](SECURITY.md) | Security policy & responsible disclosure |

## 🤝 Contributing

We believe the best security tools are built by the community.

```bash
# Fork, clone, and create your branch
git checkout -b feature/amazing-feature

# Make your changes, test them
pytest

# Submit a PR
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas we'd love help with:**
- 🔌 New MCP adapters (Nuclei, SQLMap, etc.)
- 🌍 Internationalization
- 📊 Reporting templates
- 🧪 Test coverage
- 📚 Documentation & tutorials

## ⚠️ Legal & Ethical Use

<div align="center">

**This tool is for authorized security testing only.**

</div>

- ✅ Use on systems you own or have written permission to test
- ✅ Follow responsible disclosure practices
- ✅ Comply with all applicable laws and regulations
- ❌ Never use for unauthorized access
- ❌ Never use for malicious purposes

**The human-in-the-loop design is not just for safety — it's for accountability.**
You are responsible for every action you approve.

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built on [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) by Anthropic
- Inspired by [PentestGPT](https://github.com/GreyDGL/PentestGPT) and the security research community
- Powered by the incredible open-source security ecosystem

---

<div align="center">

### The future of pentesting isn't about replacing humans with AI.
### It's about making humans and AI work together — safely.

<br>

```bash
git clone https://github.com/cawa102/VibeHackAI.git && cd VibeHackAI && pip install -e . && pentest-agent
```

**[⭐ Star this repo](https://github.com/cawa102/VibeHackAI)** if you believe in human-AI collaboration!

<br>

Made with 🔐 by security researchers, for security researchers.

<br>

[![GitHub stars](https://img.shields.io/github/stars/cawa102/VibeHackAI?style=social)](https://github.com/cawa102/VibeHackAI/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/cawa102/VibeHackAI?style=social)](https://github.com/cawa102/VibeHackAI/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/cawa102/VibeHackAI?style=social)](https://github.com/cawa102/VibeHackAI/watchers)

</div>
