# GitHub Discussions Setup Guide

Copy-paste these when setting up GitHub Discussions.

---

## Category Descriptions

When creating categories in Settings → Discussions → Categories:

| Category | Format | Description |
|----------|--------|-------------|
| **Announcements** | Announcement | Project updates and releases |
| **Pentest Results** | Open-ended | Share your pentest experiences |
| **Q&A** | Question/Answer | Get help from the community |
| **Ideas** | Open-ended | Suggest new features or improvements |
| **Show & Tell** | Open-ended | Share interesting findings or workflows |

---

## Welcome Post (Pin to Announcements)

### Title:
```
Welcome to VibeHackAI Discussions
```

### Body:
```markdown
Welcome to the VibeHackAI community!

This is the place to share experiences, ask questions, and help shape the future of human-AI collaborative pentesting.

## How to Use Discussions

| Category | When to Use |
|----------|-------------|
| **Pentest Results** | Share your test experiences, what worked, what didn't |
| **Q&A** | Ask questions about setup, usage, or troubleshooting |
| **Ideas** | Propose new features, MCP integrations, or workflows |
| **Show & Tell** | Share interesting findings, custom prompts, or creative uses |

## Guidelines

1. **Sanitize sensitive data** — Remove IPs, domains, credentials, client info
2. **Be specific** — Include versions, MCP servers used, and steps to reproduce
3. **Search first** — Check if your question was already answered
4. **Help others** — Share what you learn

## For Bugs & Feature Requests

Use [GitHub Issues](https://github.com/cawa102/VibeHackAI/issues) with our templates:
- 🐛 Bug Report
- ✨ Feature Request
- 📋 Pentest Feedback

## Stay Updated

Watch this repo for release announcements and roadmap updates.

---

Let's build the future of AI-assisted pentesting — together.
```

---

## Pentest Results - Pinned Post

### Title:
```
How to Share Your Pentest Results
```

### Body:
```markdown
This category is for sharing your real-world experiences using VibeHackAI.

## What to Share

- ✅ Target types you tested (web app, API, network, etc.)
- ✅ What worked well
- ✅ What didn't work or could be improved
- ✅ False positives / false negatives you encountered
- ✅ How the AI conversation flow felt

## What NOT to Share

- ❌ Actual target IPs, domains, or hostnames
- ❌ Credentials or secrets
- ❌ Client or organization names
- ❌ Detailed exploit payloads for unreported vulns

## Example Post Format

```
**Target Type:** Web Application (PHP, MySQL)
**MCP Servers:** nmap, burp, sqlmap

**What Worked:**
- Recon phase correctly identified tech stack
- AI suggested checking /admin before I asked

**What Didn't Work:**
- False positive on XSS in search field
- Took 3 corrections before AI focused on API

**Suggestions:**
- Add confidence scores to findings
```

Your feedback directly shapes VibeHackAI's development. Thank you for contributing!
```

---

## Q&A - Pinned Post

### Title:
```
Before You Ask - FAQ & Resources
```

### Body:
```markdown
## Quick Links

| Resource | Link |
|----------|------|
| Installation Guide | [INSTALLATION.md](https://github.com/cawa102/VibeHackAI/blob/main/INSTALLATION.md) |
| Technical Docs | [docs/](https://github.com/cawa102/VibeHackAI/tree/main/docs) |
| Examples | [examples/](https://github.com/cawa102/VibeHackAI/tree/main/examples) |
| Bug Reports | [Issues](https://github.com/cawa102/VibeHackAI/issues) |

## Frequently Asked Questions

### How do I install MCP servers?

See [INSTALLATION.md](https://github.com/cawa102/VibeHackAI/blob/main/INSTALLATION.md) for detailed setup instructions.

### Which MCP servers are supported?

Currently: Nmap, Shodan, Burp Suite, Metasploit, Kali, Snyk, CVE-Search, GitHub, GitLab, and more.

### How do I report a bug?

Use [GitHub Issues](https://github.com/cawa102/VibeHackAI/issues/new?template=bug_report.md) with the Bug Report template.

### Can I use this for production pentests?

VibeHackAI is in early development (v0.1.0). Use at your own risk and always verify findings manually.

---

## Asking Good Questions

1. **Include your environment** — OS, Python version, MCP servers
2. **Show what you tried** — Commands, errors, logs
3. **Be specific** — "X doesn't work" → "When I do X, I expect Y but get Z"

The more details you provide, the faster you'll get help!
```

---

## Ideas - Pinned Post

### Title:
```
Feature Ideas & Roadmap Discussion
```

### Body:
```markdown
Have an idea to make VibeHackAI better? Share it here!

## What We're Looking For

- 🔌 **New MCP integrations** — Nuclei, SQLMap, Gobuster, etc.
- 🤖 **AI improvements** — Better prompts, smarter decisions
- 📊 **Reporting** — New formats, templates, visualizations
- 🔒 **Safety features** — Additional guardrails, checks
- 🌍 **Internationalization** — Language support

## How to Propose an Idea

1. **Check existing ideas** — Avoid duplicates, upvote existing ones
2. **Describe the problem** — What limitation are you facing?
3. **Propose a solution** — How would you solve it?
4. **Show use cases** — When would this be useful?

## Current Priorities

Check [docs/](https://github.com/cawa102/VibeHackAI/tree/main/docs) for implementation tickets and roadmap.

---

Your ideas shape the future of VibeHackAI!
```

---

## Show & Tell - Pinned Post

### Title:
```
Share Your Wins!
```

### Body:
```markdown
Found something cool with VibeHackAI? Share it here!

## What to Share

- 🎯 Interesting vulnerabilities you found
- 💬 Clever prompts or conversation strategies
- 🔧 Custom workflows or configurations
- 📝 Report templates you created
- 🎓 Lessons learned

## Guidelines

- **Sanitize everything** — No real targets, IPs, or client info
- **Be educational** — Explain why it's interesting
- **Give credit** — Link to relevant resources

---

Let's learn from each other!
```
