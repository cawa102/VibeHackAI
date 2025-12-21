# 004: Patch Protocol

## Overview

Implements a mechanism for state update proposals (Patches) from Agents to Orchestrator. Performs conflict avoidance and safety verification using optimistic locking.

## Purpose

- Enable Agent output to be mechanically applicable
- Suppress conflicts, duplicates, and erroneous updates
- Early detection of dangerous operations

## Scope

### In-Scope

- Definition of Patch structure
- Optimistic locking (base_state_version verification)
- Verification logic by Orchestrator
- Patch application processing

### Out-of-Scope

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
|------|------|------|
| `add_evidence` | Add Evidence | EvidenceItem |
| `add_observation` | Add observation record | Observation |
| `update_target_profile` | Update target information | TargetProfile |
| `add_vuln_candidate` | Add vulnerability candidate | VulnCandidate |
| `add_exploit_candidate` | Add Exploit candidate | ExploitCandidate |
| `propose_execution_plan` | Propose execution plan | ExecutionPlan |
| `record_execution_result` | Record execution result | ExecutionResult |
| `add_finding_candidate` | Add finding candidate | FindingCandidate |
| `promote_finding_candidate` | Promote finding candidate | FindingCandidate |
| `add_decision_trace` | Add decision-making record | DecisionTrace |

## Verification Rules

1. **Version verification**: `base_state_version` matches current State version
2. **Scope verification**: Operation target is within Scope
3. **Required field verification**: Required fields exist in payload
4. **Evidence verification**: Evidence referenced by evidence_ids exists
5. **Approval requirement verification**: Dangerous operations have `requires_approval` set
6. **Duplication verification**: Object with same ID does not already exist

## Implementation Tasks

- [x] Patch structure definition
  - [x] Patch class implementation
  - [x] PatchOperation class implementation
  - [x] Operation type Enum definition
- [x] Optimistic locking implementation
  - [x] state_version management
  - [x] Rejection processing on version mismatch
  - [x] Error message on conflict
- [x] Verification engine implementation
  - [x] Scope verification
  - [x] Required field verification
  - [x] Evidence existence verification
  - [x] Approval requirement verification
  - [x] Duplication verification
- [x] Patch application engine implementation
  - [x] add_evidence application
  - [x] add_observation application
  - [x] update_target_profile application
  - [x] add_vuln_candidate application
  - [x] add_exploit_candidate application
  - [x] propose_execution_plan application
  - [x] record_execution_result application
  - [x] add_finding_candidate application
  - [x] promote_finding_candidate application
  - [x] add_decision_trace application
- [x] Atomic update
  - [x] Transactional application
  - [x] Rollback on failure
  - [x] Version increment
- [x] Audit log
  - [x] Record Patch application history
  - [x] Record rejection reason
- [x] Unit tests
  - [x] Application test for each operation
  - [x] Version mismatch test
  - [x] Scope violation test
  - [x] Evidence missing test
  - [x] Approval requirement missing test

## Acceptance Criteria

- [x] [AC-3] Patch is rejected on base_state_version mismatch (conflict avoidance)

## Dependencies

- 001_shared_workspace (State Store)
- 002_common_schema (Schema definitions)

## Related Files

```
/src/patch/
  __init__.py
  patch.py
  operations.py
  validator.py
  applier.py
  audit_log.py

/tests/patch/
  __init__.py
  test_patch.py
  test_validator.py
  test_applier.py
  test_audit_log.py
```

## Notes

- Return detailed error message on verification failure
- Do not perform partial application (All or Nothing)
- Return new state_version on successful application
