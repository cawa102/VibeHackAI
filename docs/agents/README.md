# PentestAgent - Agent Definitions

## Overview

PentestAgent is a multi-agent penetration testing support system consisting of 4 specialized agents.
Each agent has clearly defined roles and responsibilities, operating cooperatively under the control of the Orchestrator.

## Agent Architecture

```
                    ┌─────────────────────┐
                    │    Orchestrator     │
                    │  (Control Plane)    │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Reconnaissance │  │   Enumeration   │  │     Planner     │
│     Agent       │  │     Agent       │  │     Agent       │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Exploitation   │
                    │     Agent       │
                    └─────────────────┘
```

## Agent Summary

| Agent | Purpose | Key MCP | Approval Required |
|-------|---------|---------|-------------------|
| [Reconnaissance](./reconnaissance_agent.md) | External observation & service detection | Shodan, OSINT, Nmap | No (active scan only) |
| [Enumeration](./enumeration_agent.md) | Web/API/authentication boundary identification | Burp, Nmap | No |
| [Planner](./planner_agent.md) | Vulnerability analysis & execution plan creation | Snyk, CVE, GitHub | No |
| [Exploitation](./exploitation_agent.md) | Exploit execution & verification | Metasploit, Kali | **Yes** |

## Execution Flow

```
1. User provides Target IP
           │
           ▼
2. Reconnaissance Agent
   - Passive collection (Shodan/OSINT)
   - Active scan (Nmap)
   - Update TargetProfile
           │
           ▼
3. Enumeration Agent
   - Sitemap discovery
   - Parameter analysis
   - Auth/authz mapping
           │
           ▼
4. Planner Agent
   - CVE/vulnerability search
   - PoC/Exploit discovery
   - Execution plan generation
           │
           ▼
5. Exploitation Agent (requires approval)
   - Execute approved steps
   - Collect evidence
   - Document findings
           │
           ▼
6. Report Generation
```

## Common Interface

### Context Bundle (Input)

All agents receive a Context Bundle from the Orchestrator:

```json
{
  "session_id": "pentest-20251219-123456",
  "scope": { ... },
  "target_profile": { ... },
  "key_evidence_refs": ["ev-..."],
  "constraints": { ... }
}
```

### Patch (Output)

All agents return a Patch to the Orchestrator:

```json
{
  "patch_type": "update_target_profile",
  "base_state_version": "v5",
  "changes": { ... },
  "evidence_ids": ["ev-..."],
  "scope_tag": "in-scope"
}
```

## Shared Principles

### 1. Scope Compliance
- All operations are executed within the defined scope
- Immediate stop when out-of-scope is detected

### 2. Evidence-First
- All assertions are backed by Evidence
- Integrity is ensured with sha256 hash

### 3. Minimal Privilege
- Each agent uses only permitted MCPs
- Execute only the minimum necessary operations

### 4. Human-in-the-Loop
- Destructive operations require approval
- Escalate when uncertainty is high

### 5. Reproducibility
- All operations are recorded in a reproducible format
- Include reproduction steps in Evidence

## Error Handling

Common error classifications:

| Error Class | Description | Default Action |
|-------------|-------------|----------------|
| `network` | Connection and reachability issues | Retry → Alternative approach |
| `auth` | Authentication and authorization issues | Return for correction |
| `scope` | Scope violation | Immediate stop |
| `parse` | Data parsing error | Log and continue |
| `unknown` | Unclassifiable | Escalate |

## Files

- [reconnaissance_agent.md](./reconnaissance_agent.md) - Reconnaissance Agent Definition
- [enumeration_agent.md](./enumeration_agent.md) - Enumeration Agent Definition
- [planner_agent.md](./planner_agent.md) - Planner Agent Definition
- [exploitation_agent.md](./exploitation_agent.md) - Exploitation Agent Definition
