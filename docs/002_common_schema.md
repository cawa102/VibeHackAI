# 002: Common Schema (Type Definitions)

## Overview

Defines common data schemas used across the entire system. All objects have unified fields and structures.

## Purpose

- Type-safe data exchange between Agent/Orchestrator
- Ensure consistency through mandatory field enforcement
- Backward compatibility through schema version management

## Scope

### In Scope

- Type definitions for all common objects
- Validation functions
- Schema version management

### Out of Scope

- MCP output normalization (implemented in Passer)
- Patch operation logic (implemented in Patch Protocol)

## Required Objects

### Common Fields (Required for All Objects)

```python
class BaseSchema:
    id: str                  # UUID v4
    session_id: str          # Session ID
    created_at: datetime     # Creation datetime (ISO 8601)
    created_by: str          # Creator (agent name or "orchestrator" or "human")
    scope_tag: str           # Scope tag (target identifier)
    schema_version: str      # Schema version (semver)
```

### Context Bundle Fields

| Field | Required | Description |
|-------|----------|-------------|
| session_id | Yes | Session identifier |
| state_version | Yes | Version for optimistic locking |
| scope_tag | Yes | Target identification tag |
| scope | Yes | Permitted targets and actions |
| allowed_tools | Yes | Tools permitted for this agent/phase |
| target_profile | No | Recon results (from Enumeration onward) |
| approved_execution_plan | No | Approved plan (during Exploitation) |
| instructions | Yes | Instructions to agent |

### TestPlan Fields (Planner)

| Field | Required | Description |
|-------|----------|-------------|
| plan_id | Yes | Plan identifier |
| version | Yes | Version number (incremented on each update) |
| session_id | Yes | Session identifier |
| scope_summary | Yes | Scope summary |
| target_description | Yes | Target description |
| primary_objective | Yes | Primary objective |
| phase_sequence | Yes | Phase array (recon, enum, exploit) |
| change_log | Yes | Change history |

### Phase Status (Planner)

| Status | Description |
|--------|-------------|
| `pending` | Not started |
| `in_progress` | In progress |
| `completed` | Completed |
| `suspended` | Suspended |

### ExecutionPlan Fields (Planner)

| Field | Required | Description |
|-------|----------|-------------|
| name | Yes | Plan name |
| objective | Yes | Objective |
| priority | Yes | Priority (1=highest) |
| exploit_candidate_id | Yes | Related ExploitCandidate |
| vuln_candidate_id | Yes | Related VulnCandidate |
| cvss_estimate | Yes | CVSS evaluation |
| steps | Yes | Step array |
| estimated_success_rate | Yes | Success probability (0-1) |
| rationale | Yes | Rationale |
| evidence_ids | Yes | Evidence IDs |

### Step Fields

| Field | Required | Description |
|-------|----------|-------------|
| step_id | Yes | Step identifier |
| order | Yes | Execution order |
| action | Yes | Action name |
| description | Yes | Detailed description |
| tool | Yes | Tool to use |
| parameters | Yes | Parameters |
| requires_approval | Yes | Requires approval |
| expected_outcome | Yes | Expected outcome |
| success_criteria | Yes | Success criteria |
| fallback | No | Fallback on failure |
| rollback | No | Rollback procedure |
| depends_on | No | Dependent steps |

### entry_point_inventory Fields (Reconnaissance)

| Field | Required | Description |
|-------|----------|-------------|
| session_id | Yes | Session ID |
| target | Yes | Target identifier |
| total_entry_points | Yes | Total entry point candidates |
| by_category | Yes | Entry point candidates by category |
| priority_summary | Yes | Priority summary (critical/high/medium/low) |

### technology_stack Fields (Reconnaissance)

| Field | Required | Description |
|-------|----------|-------------|
| target | Yes | Target identifier |
| detected_at | Yes | Detection datetime |
| components | Yes | Detected components (web_server, language, framework, etc.) |
| security_relevant | Yes | Security-relevant info (outdated_components, waf_bypass_notes) |

### handoff_summary Fields (Reconnaissance)

| Field | Required | Description |
|-------|----------|-------------|
| session_id | Yes | Session ID |
| from | Yes | "reconnaissance-agent" |
| to | Yes | "enumeration-agent" |
| target_count | Yes | Target count |
| entry_points_total | Yes | Total entry point candidates |
| priority_breakdown | Yes | Priority breakdown |
| key_findings | Yes | Key findings list |
| recommended_focus | Yes | Recommended focus areas |
| anomalies_for_review | Yes | Anomalies requiring review count |
| evidence_ids | Yes | Evidence ID list |

### FindingCandidate Fields (Enumeration)

| Field | Required | Description |
|-------|----------|-------------|
| title | Yes | Finding title |
| severity | Yes | high/medium/low/info |
| description | Yes | Detailed description |
| affected_endpoint | Yes | Affected endpoint |
| reproduction_steps | Yes | Reproduction steps list |
| evidence_ids | Yes | Evidence IDs (2 or more) |
| reproducibility | Yes | status, attempts, success_rate |

### hypothesis_validation Fields (Exploitation)

| Field | Required | Description |
|-------|----------|-------------|
| vuln_candidate_id | Yes | VulnCandidate ID to validate |
| validation_status | Yes | ESTABLISHED / PARTIAL / NOT_ESTABLISHED / INCONCLUSIVE |
| executability.verified | Yes | Executability verification result |
| executability.method | Yes | Verification method used |
| executability.evidence_id | Yes | Evidence ID |
| impact_proof.verified | Yes | Impact proof verification result |
| impact_proof.impact_type | Yes | Impact type (data_extraction, etc.) |
| impact_proof.evidence_id | Yes | Evidence ID |
| confidence | Yes | high / medium / low |
| next_action | Yes | Next action |

### Approval Request Fields (Exploitation)

| Field | Required | Description |
|-------|----------|-------------|
| id | Yes | Approval request ID |
| type | Yes | privilege_escalation / lateral_movement |
| current_access | Yes | Current access level/privileges |
| target_access | Yes | Target access level |
| poc_description | Yes | PoC execution description |
| poc_command | Yes | Command to execute |
| risk_assessment.risk_level | Yes | low / medium / high / critical |
| risk_assessment.reversibility | Yes | Operation reversibility description |
| risk_assessment.scope_compliance | Yes | Scope compliance confirmation |
| expected_outcome | Yes | Expected outcome |
| fallback_plan | No | Fallback plan on failure |


### Defined Objects

1. **Scope** - Permitted target range
2. **TargetProfile** - Target detailed information
3. **EvidenceItem** - Evidence data metadata
4. **Observation** - MCP execution result observation record
5. **VulnCandidate** - Vulnerability candidate
6. **ExploitCandidate** - Exploit candidate
7. **ExecutionPlan** - Execution plan
8. **ExecutionResult** - Execution result
9. **FindingCandidate** - Finding candidate
10. **DecisionTrace** - Decision record

## Acceptance Criteria

- [x] [AC-5] FindingCandidates rated high/critical cannot be created/promoted unless Evidence requirements are met

## Dependencies

- 001_shared_workspace (for EvidenceItem reference)

## Related Files

```
/src/
  schemas/
    __init__.py
    base.py
    scope.py
    target_profile.py
    evidence.py
    observation.py
    vuln_candidate.py
    exploit_candidate.py
    execution_plan.py
    execution_result.py
    finding_candidate.py
    decision_trace.py
    validators.py
```

## Notes

- Use Pydantic to ensure type safety
- schema_version starts at "1.0.0"
- Critical claims (Findings, etc.) must always be accompanied by evidence_ids
