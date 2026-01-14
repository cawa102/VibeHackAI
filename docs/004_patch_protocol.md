# 004: Patch Protocol

## Overview

Implements a mechanism for Agents to propose state updates (Patches) to the Orchestrator. Performs conflict avoidance through optimistic locking and safety validation.

## Purpose

- Enable mechanical application of Agent outputs
- Suppress conflicts, duplicates, and erroneous updates
- Pre-detect dangerous operations

## Scope

### In Scope

- Patch structure definition
- Optimistic locking (base_state_version verification)
- Validation logic by Orchestrator
- Patch application processing

### Out of Scope

- Patch generation logic on Agent side (implemented in each Agent)
- Approval gate UI (implemented in Orchestrator)

## Patch Structure

```python
class Patch:
    patch_id: str
    session_id: str
    agent_id: str
    base_state_version: int
    operations: List[PatchOperation]
    created_at: datetime

class PatchOperation:
    op: str  # Operation type
    target: str  # Target (schema name/ID, etc.)
    payload: dict  # Operation data
```

## Patch Operations List

| Operation | Description | Target |
|-----------|-------------|--------|
| `add_evidence` | Add Evidence | EvidenceItem |
| `add_observation` | Add observation record | Observation |
| `update_target_profile` | Update target info | TargetProfile |
| `add_vuln_candidate` | Add vulnerability candidate | VulnCandidate |
| `add_exploit_candidate` | Add exploit candidate | ExploitCandidate |
| `propose_execution_plan` | Propose execution plan | ExecutionPlan |
| `record_execution_result` | Record execution result | ExecutionResult |
| `add_finding_candidate` | Add finding candidate | FindingCandidate |
| `promote_finding_candidate` | Promote finding candidate | FindingCandidate |
| `add_decision_trace` | Add decision record | DecisionTrace |

## Validation Rules

1. **Version Validation**: `base_state_version` matches current State version
2. **Scope Validation**: Operation target is within Scope
3. **Required Field Validation**: Required fields exist in payload
4. **Evidence Validation**: Evidence referenced by evidence_ids exists
5. **Approval Requirement Validation**: `requires_approval` is set for dangerous operations
6. **Duplicate Validation**: Object with same ID does not already exist

## Acceptance Criteria

- [x] [AC-3] Patches are rejected on base_state_version mismatch (conflict avoidance)

## Dependencies

- 001_shared_workspace (State Store)
- 002_common_schema (schema definitions)

## Notes

- Return detailed error messages on validation failure
- No partial application (All or Nothing)
- Return new state_version on successful application
