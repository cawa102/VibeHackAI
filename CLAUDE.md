# CLAUDE.md

Guidance for the MCP-integrated multi-agent penetration testing support system.

---

## 1. Quick Start

### What Is This System?

An interactive penetration testing support system consisting of 4 agents (Planner / Reconnaissance / Enumeration / Exploitation) + Orchestrator with human oversight.

**Purpose**: Rather than "attack automation," this system prioritizes **scope compliance, safety, evidence collection, and reproducibility** by governing LLM reasoning and tool execution for efficient penetration testing.

### Session Initialization

After the human provides target information, launch the Orchestrator to begin the penetration test.

---

## 2. System Overview

### Architecture

```
Orchestrator (Control Plane - Single Writer)
├── Human Interface (Approval & Interaction)
├── Routing/Coordination (Phase Transitions)
└── State/Evidence Management (Sole Write Authority)

Agents (4 total)
├── Planner Agent
├── Reconnaissance Agent
├── Enumeration Agent
└── Exploitation Agent

Shared Workspace (Common Area)
├── State Store (Normalized State)
├── Evidence Store (Raw Data - Append-Only)
└── Retrieval Cache (Query Result Cache)

MCP Servers
├── GitHub
├── hexstrike-ai
└── Filesystem

**Available tools via hexstrike-ai are documented in [docs/tool_manifest.yaml](docs/tool_manifest.yaml)**
```

### Scope

**In Scope**:
- Reconnaissance, enumeration, vulnerability assessment, and exploitation against tester-authorized targets (IP/CIDR/Domain)
- PoC program creation and testing (approval required)
- Evidence collection and report generation

**Out of Scope**:
- Indiscriminate/large-scale scanning, DoS, persistence, data exfiltration, autonomous execution
- Destructive operations or payload distribution without human approval

---

## 3. Safety Rules

### Mandatory Requirements

1. **Scope Enforcement**: Attach `scope_tag` to all actions; immediately halt upon out-of-scope detection
2. **Evidence Obligation**: Evidence is append-only; Findings must be backed by evidence_id

### Stop Conditions

| Condition | Action |
|-----------|--------|
| Consecutive error threshold (same error_class 2 times) | Halt → Human escalation |
| Scope ambiguity | Immediate halt → Human notification |
| DoS indicators | Immediate halt → Human notification |
| Unknown destructive behavior | Immediate halt → Human notification |

---

## 5. Data Specifications

### Shared Workspace Structure

```
/workspace/sessions/<session_id>/
  state/          # Normalized state (Orchestrator write-only)
    scope.json
    target_profile.json
    candidates_vuln.json
    candidates_exploit.json
    execution_plans.json
    findings.json
    state_version.json
  evidence/       # Raw data (append-only, with sha256)
    <evidence_id>/
      raw.<ext>
      meta.json
  cache/          # Query result cache
  reports/        # Report output
```

### Common Schema Reference
Common schemas for safe inter-agent data exchange are documented in `docs/002_common_schema.md`.
Common fields across all schemas: `id`, `session_id`, `created_at`, `created_by`, `scope_tag`, `schema_version`

### Patch Protocol

**Principle**: Agents return **Patches only**. Direct state updates are prohibited.

**Operations**:
- `add_evidence` - Add evidence
- `add_observation` - Record MCP execution
- `update_target_profile` - Update target information
- `add_vuln_candidate` - Add vulnerability candidate
- `add_exploit_candidate` - Add exploit candidate
- `propose_execution_plan` - Propose execution plan
- `record_execution_result` - Record execution result
- `add_finding_candidate` - Add finding
- `promote_finding_candidate` - Promote finding
- `add_decision_trace` - Record decision rationale


---

## 6. Code of Conduct

**This code of conduct applies to all sub-agents (Orchestrator, Planner, Reconnaissance, Enumeration, Exploitation)**

### Persistence Policy

**Principle**: Do not give up after a single failure

**Failure Response Flow**:
1. Deeply analyze the reason for failure and identify the root cause
2. Consider alternative approaches, tools, or payloads
3. Escalate progressively:
   - 1st failure: Try a different method
   - 2nd failure: Consider yet another approach
   - 3rd+ failures: Consult and re-evaluate strategy

**Prohibited Actions**:
- Do not conclude "this vulnerability does not exist" after a single failure
- Do not end a phase without considering alternatives
- Do not modify the test plan without approval

### Post-Exploitation Loop

**Principle**: Do not immediately proceed to report generation after successful exploitation

**Workflow**:
```
Exploitation Result → Orchestrator → Planner
    ↓
Planner considers additional tests
    ↓
Additional Test Plan → Orchestrator → Human Approval
    ↓
Approved → Execute additional tests (loop)
Rejected/Skipped → Generate final report
```

**Exit Conditions** (exit only when all conditions are met):
- All additional attacks leveraging obtained access have been considered
- Human explicitly rejected/skipped additional tests

---

## 7. Reference Information

### Detailed Specification Links

| Document | Contents |
|----------|----------|
| [docs/001_shared_workspace.md](docs/001_shared_workspace.md) | Shared Workspace + Evidence Ledger Specification |
| [docs/002_common_schema.md](docs/002_common_schema.md) | Common Schema Type Definitions |
| [docs/003_passer.md](docs/003_passer.md) | Normalization Engine Specification |
| [docs/004_patch_protocol.md](docs/004_patch_protocol.md) | Patch Protocol Specification |
| [.claude/agents/pentest-orchestrator.md](.claude/agents/pentest-orchestrator.md) | Orchestrator Specification |
| [.claude/agents/reconnaissance-agent.md](.claude/agents/reconnaissance-agent.md) | Reconnaissance Agent Specification |
| [.claude/agents/enumeration-agent.md](.claude/agents/enumeration-agent.md) | Enumeration Agent Specification |
| [.claude/agents/planner-agent.md](.claude/agents/planner-agent.md) | Planner Agent Specification |
| [.claude/agents/exploitation-agent.md](.claude/agents/exploitation-agent.md) | Exploitation Agent Specification |
