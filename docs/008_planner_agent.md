# 008: Planner Agent

## Overview

Implement an Agent that searches for vulnerability candidates, evaluates feasibility, and formulates exploit plans.

## Purpose

- Identify vulnerability candidates based on TargetProfile
- Cross-reference with CVE/Snyk databases
- Search for exploit candidates (GitHub/GitLab)
- Formulate execution plan (ExecutionPlan)

## Responsibilities

### Areas of Responsibility

- Vulnerability database queries
- Feasibility assessment (version, prerequisites)
- Search for PoC/Exploit candidates
- Formulation of execution plans

### Not Responsible For

- Information gathering (performed in Recon/Enumeration)
- Exploit execution (performed in Exploitation)

## MCPs Used

| MCP | Purpose | Priority |
|-----|---------|----------|
| MCP-snyk / Snyk CLI | Vulnerability reference | High |
| CVE-research-MCP | CVE detail queries | High |
| GitHub-MCP | PoC/Exploit search | High |
| GitLab MCP | PoC/Exploit search | Medium |
| Shodan-MCP | Exposure reconfirmation | Low |

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

- `add_evidence`: Vulnerability information, PoC information, etc.
- `add_observation`: Query records
- `add_vuln_candidate`: Vulnerability candidates
- `add_exploit_candidate`: Exploit candidates
- `propose_execution_plan`: Execution plan
- `add_decision_trace`: Selection rationale

## Processing Flow

1. Extract technology stack from TargetProfile
2. Vulnerability queries:
   a. Check dependency vulnerabilities with Snyk
   b. Query service/version vulnerabilities with CVE-research
3. Feasibility assessment:
   a. Version matching
   b. Confirm prerequisites (authentication requirements, reachability, etc.)
4. Exploit search:
   a. Search for PoCs on GitHub/GitLab
   b. Reliability assessment (star count, update date, etc.)
5. Formulate execution plan:
   a. Prioritization (CVSS, feasibility, impact)
   b. Set requires_approval
   c. Rollback procedures
6. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] Implement PlannerAgent class
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Snyk integration
  - [x] Implement Snyk MCP adapter
  - [x] Dependency scanning
  - [x] Save results as Evidence
  - [x] VulnCandidate conversion
- [x] CVE-research integration
  - [x] Implement CVE-research MCP adapter
  - [x] CVE queries
  - [x] Save results as Evidence
  - [x] VulnCandidate conversion
- [x] GitHub integration
  - [x] Implement GitHub MCP adapter
  - [x] PoC/Exploit search
  - [x] Reliability assessment
  - [x] ExploitCandidate conversion
- [ ] GitLab integration (Priority: Medium)
  - [ ] Implement GitLab MCP adapter
  - [ ] PoC/Exploit search
  - [ ] ExploitCandidate conversion
- [x] Feasibility assessment
  - [x] Version comparison logic
  - [x] Prerequisite check
  - [x] Calculate confidence_level
- [x] Execution plan formulation
  - [x] Priority scoring
  - [x] Step breakdown
  - [x] requires_approval determination
  - [x] Rollback procedure generation
- [x] Error handling
  - [x] Retry on MCP failure (implemented in BaseMCPAdapter)
  - [x] Processing when no candidates found
- [x] Unit tests
  - [x] Test each MCP integration (mocked)
  - [x] Feasibility assessment test
  - [x] Execution plan generation test

## Stop Conditions

- No vulnerability candidates (suggest stop as normal completion)
- No exploit candidates (end with VulnCandidate only)
- Consecutive MCP failures (2 times)

## Quality Gates

- VulnCandidate must have evidence_ids
- ExploitCandidate linked with vuln_candidate_id
- ExecutionPlan has requires_approval for dangerous steps

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schema)
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

- PoC acquisition at Planner stage is reference only (execution in Exploitation)
- Mark unverified PoCs with "low" reliability
- Plan in order of severity when multiple vulnerabilities exist
