# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP-Integrated Multi-Agent Penetration Testing Support System

An interactive penetration testing support system with **4 agents (Planner / Reconnaissance / Enumeration / Exploitation) + Orchestrator**.

This system is not about "attack automation," but rather prioritizes **scope, safety, evidence, and reproducibility** with the goal of governing LLM reasoning and tool execution.

## Scope of Application

### In-Scope
- For targets (IP/CIDR/Domain) authorized by the tester:
  - Recon (passive OSINT + minimum necessary active investigation)
  - Enumeration (understanding app/entry points/authorization boundaries)
  - Vulnerability candidate discovery and feasibility assessment (CVE/Snyk, etc.)
  - Exploitation (verification of approved procedures/Kali execution/prerequisite collection for exploits/exploitation/debug)
  - Evidence collection and report material generation

### Out-of-Scope
- Indiscriminate/large-scale scanning, DoS, persistence, data exfiltration, autonomous execution of lateral movement
- Destructive operations or payload distribution without human approval

## Architecture

### Component Configuration

```
Orchestrator (Required)
├── Human Interface
├── Routing/Coordination
├── State/Evidence Management
├── Approval Gate
└── Stop Conditions

Agents (4)
├── Planner Agent
├── Reconnaissance Agent
├── Enumeration Agent
└── Exploitation Agent

Shared Workspace (Common Area)
├── State Store (Normalized State)
├── Evidence Store (Raw Data, Append-Only)
└── Retrieval Cache (Cache for Query Result Reproduction)

MCP Servers (Existing)
├── Nmap / Shodan / OSINT
├── Snyk / CVE-research
├── GitHub / GitLab
├── Burpsuite / Metasploit / Kali
└── Filesystem / Logs / Passer
```

### MCP Server Usage Policy

| Agent | MCP Used |
|-------|---------|
| Orchestrator | Filesystem / Logs / Passer MCPs |
| Reconnaissance | Shodan-MCP, OSINT-MCP, Nmap MCP |
| Enumeration | Burpsuit-MCP, Nmap MCP, OSINT-MCP, GitHub/GitLab MCP |
| Planner | MCP-snyk, CVE-research-MCP, GitHub/GitLab MCP, Shodan-MCP |
| Exploitation | Metasploit-MCP, MCP-kali-server, Burpsuit-MCP, GitHub/GitLab MCP |

## Safety and Governance (Mandatory Requirements)

### Scope Management
- **Scope** is maintained in State, and all actions are tagged with `scope_tag`
- If out-of-scope target/operation is detected, stop immediately and notify Human

### Approval Gate (Human-in-the-loop)
The following require human approval before execution:
- Metasploit execution (module execution)
- Operations that may involve payload delivery or persistence
- High-frequency requests, brute force, suspected DoS
- Operations with high probability of file modification, configuration changes, privilege escalation

Approval subjects are expressed in `ExecutionPlan.step.requires_approval`.

### Evidence and Tamper Resistance
- Evidence is **append-only**, always save `sha256`
- Finding assertions must **always be backed by evidence_id**

### Secret Information
- Do not store in plaintext in State
- Only `secret_ref` references, Evidence/Logs are masked

## Shared Workspace Specifications

### Directory Structure

```
/workspace/sessions/<session_id>/
  state/
    scope.json
    target_profile.json
    candidates_vuln.json
    candidates_exploit.json
    execution_plans.json
    execution_results.jsonl
    observations.jsonl
    findings.json
    decision_traces.jsonl
    state_version.json
    context_bundles/
      recon/<ts>.json
      enumeration/<ts>.json
      planner/<ts>.json
      exploitation/<ts>.json
  evidence/
    <evidence_id>/
      raw.<ext>
      meta.json
  cache/
    cve/<query_hash>.json
    snyk/<query_hash>.json
    git/<query_hash>.json
  reports/
    draft.md
```

### Update Principles
- **Only Orchestrator writes to State (Single Writer)**
- Agents return only **Patch (proposed diff)**
- Finalized references (State reflection) are performed by Orchestrator

## Common Schema Requirements

Required objects:
- Scope
- TargetProfile
- EvidenceItem
- Observation
- VulnCandidate
- ExploitCandidate
- ExecutionPlan
- ExecutionResult
- FindingCandidate
- DecisionTrace (recommended)

Common fields:
- `id`, `session_id`, `created_at`, `created_by`, `scope_tag`, `schema_version`
- Critical assertions are accompanied by `evidence_ids`

## Patch Protocol

### Patch Operations
- `add_evidence`
- `add_observation`
- `update_target_profile`
- `add_vuln_candidate`
- `add_exploit_candidate`
- `propose_execution_plan`
- `record_execution_result`
- `add_finding_candidate`
- `promote_finding_candidate`
- `add_decision_trace`

### Validation Items
- Scope violations
- Missing required fields (missing evidence, etc.)
- Conflicts (base_state_version mismatch)
- Dangerous actions (requires approval needed but missing requires_approval, etc.)

## Execution Control

### Phase Transitions
```
Recon → Enumeration → Planner → Exploitation
- After each phase ends, return to Orchestrator, Orchestrator passes the results to Planner.
- Planner reconstructs the plan based on the results
```

Rollback conditions:
- Version undefined → Return to Recon
- Insufficient reproduction procedure (req/res missing) → Return to Enumeration
- Exploit failure due to prerequisite mismatch → Return to Planner/Enumeration

### Stop Conditions (Mandatory)
- Consecutive error threshold (same error_class 2 times) stops and escalates to Human
- Immediate stop on scope suspicion, DoS signs, unknown destructive behavior

## Repository Structure

```
/docs/                 # Tickets (feature-specific task management)
/spec/                 # Specifications (md)
/src/
  orchestrator/
  agents/
  mcp_adapters/
  passer/
  storage/
  ui_cli/
/tests/
  unit/
  integration/
  fixtures/
```

## Ticket Management

### Ticket List (/docs/)

| No. | File | Content |
|-----|---------|------|
| 001 | `001_shared_workspace.md` | Shared Workspace + Evidence Ledger |
| 002 | `002_common_schema.md` | Common Schema (type definitions) |
| 003 | `003_passer.md` | Passer (normalization engine) |
| 004 | `004_patch_protocol.md` | Patch protocol |
| 005 | `005_orchestrator.md` | Orchestrator (control plane) |
| 006 | `006_reconnaissance_agent.md` | Reconnaissance Agent |
| 007 | `007_enumeration_agent.md` | Enumeration Agent |
| 008 | `008_planner_agent.md` | Planner Agent |
| 009 | `009_exploitation_agent.md` | Exploitation Agent |

### TODO Management Rules

TODOs within each ticket file are managed in the following format:

```markdown
- [ ] Incomplete task
- [x] Completed task
```

**Operating Rules:**
- When a task is completed, change `- [ ]` to `- [x]`
- Parent tasks should only be completed after all child tasks are complete
- When adding new tasks, add them to the appropriate hierarchy
- For tasks that become unnecessary, do not delete them but leave a comment with the reason

## Implementation Order

1. Shared Workspace (Filesystem/Logs integration) + Evidence Ledger (sha256)
2. Common Schema (type definitions) + Passer (normalization)
3. Patch protocol (optimistic locking + validation)
4. Orchestrator (routing + approval gate + Context Bundle generation)
5. Recon Agent (Shodan/OSINT → Nmap)
6. Enumeration Agent (Burp-centric)
7. Planner Agent (Snyk/CVE/GitHub integration)
8. Exploitation Agent (MSF/Kali, approval gate mandatory)

## Development Rules

- Specifications (md) are "truth," code follows specifications (specification-first)
- All input/output prioritizes JSON, do not use ambiguous natural language for interfaces
- Dangerous operations must go through Orchestrator's approval policy
- Include exception cases (MCP failure, timeout, empty results) in tests from the start

## Best Practices

### Agent Development

- **Single Responsibility**: Each Agent handles only its defined role and does not violate other Agents' responsibilities
- **Idempotency**: Design to generate the same Patch for the same Context Bundle
- **Fail-fast**: Validate preconditions (required fields, scope, etc.) at the beginning of processing
- **Least Privilege**: Each Agent uses only MCPs defined in the Allowlist

### MCP Integration

- **Timeout Settings**: Set appropriate timeout for all MCP calls (30 seconds recommended default)
- **Retry Strategy**: Retry temporary errors (network, rate limits) with exponential backoff
- **Result Caching**: Utilize Retrieval Cache to avoid duplicate execution of identical queries
- **Output Normalization**: MCP raw output must be converted to common schema via Passer before State reflection

### Evidence Management

- **Immediate Save**: Save MCP execution results as Evidence before processing
- **Rich Metadata**: Record timestamp, source_tool, query_params, response_code in `meta.json`
- **Referential Integrity**: Do not delete EvidenceItem (prevent orphaned references)
- **Size Limits**: Large output (>10MB) should be saved in chunks and managed with an index

### Error Handling

- **Error Classification**: Classify by `error_class` (network/auth/scope/parse/unknown) and branch handling
- **Context Preservation**: Record State snapshot at time of error in DecisionTrace
- **Gradual Recovery**: Handle minor errors in order: skip → retry → alternative → stop
- **Human Escalation**: Immediately notify Human of difficult-to-judge errors (do not auto-decide)

### Security

- **Input Validation**: Always validate external input (including MCP results) with schema before State reflection
- **Output Sanitization**: Mask Credentials/Secrets when outputting logs/reports
- **Minimal Execution**: Exploitation executes only the minimum operations necessary for verification
- **Rollback Preparation**: Include restoration procedure in ExecutionPlan before destructive operations

### Testing

- **Phase Unit Tests**: Prepare fixtures that allow each Agent to be tested independently
- **Integration Tests**: Automated test of minimal path (Recon → Exploitation) round trip
- **Exception Cases First**: Implement tests for MCP failure/timeout/empty results before normal cases
- **Mock MCP**: Prepare mock MCP that returns deterministic responses for testing

### State Management

- **Strict Optimistic Locking**: Always validate `base_state_version` when applying Patch
- **Atomic Updates**: Execute updates of multiple fields in a single transaction
- **Version History**: Make change history trackable with `state_version.json`
- **Periodic Backups**: Save State snapshots at regular intervals during session

### Context Bundle Generation

- **Minimization Principle**: Include only information necessary for Agent, exclude unnecessary State
- **Freshness Guarantee**: Include `state_version` at time of generation to prevent use of stale Bundles
- **Schema Version**: Add `schema_version` to each object in Bundle

## Acceptance Criteria

- [AC-1] Recon → Enumeration → Planner → Exploitation completes one round in minimal case, and State/Evidence are saved
- [AC-2] Evidence is saved append-only with sha256 and can be referenced from State
- [AC-3] Patch is rejected on base_state_version mismatch (conflict avoidance)
- [AC-4] Metasploit execution is not executable without approval
- [AC-5] High/critical level FindingCandidate cannot be generated/promoted unless Evidence requirements are met
- [AC-6] Each MCP output is normalized to common schema by Passer and reflected in TargetProfile/Observation

## Quality Requirements

### Reproducibility
- FindingCandidate (high/critical) requires 2 or more Evidence
- ExecutionResult converts "command/configuration/output" to Evidence

### Auditability
- All finalized reflections go to Orchestrator's audit log
- Leave selection rationale in DecisionTrace

### Observability
- All MCP calls leave metadata as `Observation` (tool, action, evidence_id)

## Terminology

| Term | Description |
|------|------|
| Orchestrator | Control plane that connects humans and multiple agents, responsible for approval, order control, and state management |
| Evidence Ledger | Mechanism that holds raw data in append-only manner and ensures integrity with hash |
| Patch | Diff proposal that agents return to Orchestrator (direct State update is prohibited) |
| Context Bundle | Minimal context snapshot that Orchestrator passes to agents |
