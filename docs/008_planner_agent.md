# 008: Planner Agent

## Overview

Implements an Agent that searches for vulnerability candidates, evaluates feasibility, and creates exploit plans.

## Purpose

- Identify vulnerability candidates based on TargetProfile
- Cross-reference with CVE/Snyk databases
- Search for exploit candidates (GitHub/GitLab)
- Create execution plans (ExecutionPlan)

## Responsibilities

### In Scope

- Vulnerability database queries
- Feasibility evaluation (version, prerequisites)
- PoC/Exploit candidate search
- Execution plan creation

### Out of Scope

- Information gathering (done in Recon/Enumeration)
- Exploit execution (done in Exploitation)

## MCP Usage

| MCP | Purpose | Priority |
|-----|---------|----------|
| hexstrike-ai | Vulnerability reference, CVE detail queries, exposure re-confirmation | High |
| GitHub | PoC/Exploit search | High |

## Input (Context Bundle)

```python
class PlannerContextBundle:
    session_id: str
    state_version: int
    scope: Scope
    target_profile: TargetProfile  # Recon+Enumeration results
    observations: List[Observation]
    existing_vuln_candidates: List[VulnCandidate]
```

## Output (Patch)

- `add_evidence`: Vulnerability info, PoC info, etc.
- `add_observation`: Query record
- `add_vuln_candidate`: Vulnerability candidate
- `add_exploit_candidate`: Exploit candidate
- `propose_execution_plan`: Execution plan
- `add_decision_trace`: Selection rationale

## Processing Flow

1. Extract technology stack from TargetProfile
2. Vulnerability queries:
   a. Check dependency vulnerabilities with Snyk
   b. Query service/version vulnerabilities with CVE-research
3. Feasibility evaluation:
   a. Version matching
   b. Prerequisite confirmation (authentication required, reachability, etc.)
4. Exploit search:
   a. PoC search on GitHub/GitLab
   b. Reliability evaluation (star count, update date, etc.)
5. Execution plan creation:
   a. Prioritization (CVSS, feasibility, impact)
   b. Set requires_approval
   c. Rollback procedures
6. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] PlannerAgent class implementation
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Snyk integration
  - [x] Snyk MCP adapter implementation
  - [x] Dependency scan
  - [x] Evidence storage of results
  - [x] VulnCandidate conversion
- [x] CVE-research integration
  - [x] CVE-research MCP adapter implementation
  - [x] CVE queries
  - [x] Evidence storage of results
  - [x] VulnCandidate conversion
- [x] GitHub integration
  - [x] GitHub MCP adapter implementation
  - [x] PoC/Exploit search
  - [x] Reliability evaluation
  - [x] ExploitCandidate conversion
- [ ] GitLab integration (Priority: Medium)
  - [ ] GitLab MCP adapter implementation
  - [ ] PoC/Exploit search
  - [ ] ExploitCandidate conversion
- [x] Feasibility evaluation
  - [x] Version comparison logic
  - [x] Prerequisite checks
  - [x] confidence_level calculation
- [x] Execution plan creation
  - [x] Priority scoring
  - [x] Step breakdown
  - [x] requires_approval determination
  - [x] Rollback procedure generation
- [x] Error handling
  - [x] Retry on MCP failure (implemented in BaseMCPAdapter)
  - [x] No candidates handling
- [x] Unit tests
  - [x] Each MCP integration test (mock)
  - [x] Feasibility evaluation test
  - [x] Execution plan generation test

## Stop Conditions

- No vulnerability candidates (propose stop as normal completion)
- No exploit candidates (end with VulnCandidates only)
- Consecutive MCP failures (2 times)

## FR-9: Persistence Policy

**Do not give up immediately after one failure.** Follow these principles:

### Failure Response
1. Deeply analyze the failure reason and identify root cause
2. Consider alternative approaches, tools, and information sources
3. Continue attempts with alternatives even after 3+ failures

### Prohibited Actions
- Do not conclude "vulnerability does not exist" after one failure
- Do not end analysis without considering alternatives
- Do not judge "no further tests available" with only superficial investigation

## FR-10: Post-Exploitation Evaluation (Critical)

After the Exploitation phase ends, **do not immediately judge "no further tests available."**

### Required Considerations

| Category | Consideration |
|----------|---------------|
| Credential Utilization | Can obtained credentials be tried on other services (SSH, etc.)? |
| Database | Can LOAD_FILE() read system files? |
| Database | Can INTO OUTFILE place a web shell? |
| Database | Are there sensitive information in other tables? |
| Privilege Escalation | Does the MySQL user have FILE privilege? |
| Lateral Movement | Can discovered credentials be tried on other endpoints? |
| Configuration Files | Can .htpasswd, config.php, etc. be read? |
| Source Code | Can PHP file retrieval reveal additional vulnerabilities? |

### Conditions for Judging "No Further Tests Available"

Only make termination judgment when **all** of the following are met:
1. Additional attacks using obtained access have been **considered**
2. Database operation possibilities (LOAD_FILE/INTO OUTFILE) have been **verified**
3. Lateral movement possibilities have been **verified**
4. Privilege escalation possibilities have been **verified**
5. Human has **explicitly rejected/skipped** additional tests

## Quality Gates

- VulnCandidate must always have evidence_ids
- ExploitCandidate must be linked to vuln_candidate_id
- ExecutionPlan must have requires_approval on dangerous steps

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schemas)
- 003_passer (normalization)
- 005_orchestrator (caller)
- 006/007 (previous phases)

## Related Files

```
/src/agents/
  planner_agent.py
/src/mcp_adapters/
  snyk_adapter.py
  cve_adapter.py
  github_adapter.py
  gitlab_adapter.py
```

## Notes

- PoC retrieval at Planner stage is reference only (execution is in Exploitation)
- Unverified PoCs are marked as reliability "low"
- When multiple vulnerabilities exist, plan in order of severity
