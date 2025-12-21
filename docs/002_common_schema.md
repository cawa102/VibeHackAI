# 002: Common Schema (Type Definitions)

## Overview

Defines common data schemas used throughout the system. All objects have unified fields and structures.

## Purpose

- Type-safe data exchange between Agent/Orchestrator
- Consistency through enforced required fields
- Backward compatibility through schema version management

## Scope

### In-Scope

- Type definitions for all common objects
- Validation functions
- Schema version management

### Out-of-Scope

- MCP output normalization (implemented in Passer)
- Patch operation logic (implemented in Patch protocol)

## Required Objects

### Common Fields (Required for All Objects)

```python
class BaseSchema:
    id: str                  # UUID v4
    session_id: str          # Session ID
    created_at: datetime     # Creation timestamp (ISO 8601)
    created_by: str          # Creator (agent name or "orchestrator" or "human")
    scope_tag: str           # Scope tag (target identifier)
    schema_version: str      # Schema version (semver)
```

### Objects to Define

1. **Scope** - Authorized target scope
2. **TargetProfile** - Detailed target information
3. **EvidenceItem** - Evidence data metadata
4. **Observation** - MCP execution result observation record
5. **VulnCandidate** - Vulnerability candidate
6. **ExploitCandidate** - Exploit candidate
7. **ExecutionPlan** - Execution plan
8. **ExecutionResult** - Execution result
9. **FindingCandidate** - Finding candidate
10. **DecisionTrace** - Decision-making record

## Implementation Tasks

- [x] Base class implementation
  - [x] BaseSchema definition
  - [x] Common field validation
  - [x] Automatic ID generation
- [x] Scope definition
  - [x] Target list (IP/CIDR/domain)
  - [x] Allowed operations definition
  - [x] Expiration date
- [x] TargetProfile definition
  - [x] Host information (IP, hostname, OS, etc.)
  - [x] Port/service information
  - [x] Technology stack
- [x] EvidenceItem definition
  - [x] evidence_id reference
  - [x] File path
  - [x] sha256 hash
  - [x] MIME type
- [x] Observation definition
  - [x] tool name
  - [x] action name
  - [x] evidence_ids
  - [x] summary
- [x] VulnCandidate definition
  - [x] CVE ID (optional)
  - [x] Impact scope
  - [x] Severity (CVSS)
  - [x] evidence_ids
  - [x] confidence_level
- [x] ExploitCandidate definition
  - [x] vuln_candidate_id reference
  - [x] exploit_source (MSF/GitHub/manual, etc.)
  - [x] Prerequisites
  - [x] evidence_ids
- [x] ExecutionPlan definition
  - [x] steps array
  - [x] requires_approval (per step)
  - [x] Expected results
  - [x] Rollback procedure
- [x] ExecutionResult definition
  - [x] plan_id reference
  - [x] step_index
  - [x] status (success/failure/skipped)
  - [x] evidence_ids
  - [x] error_class (on failure)
- [x] FindingCandidate definition
  - [x] Title
  - [x] Severity
  - [x] Impact
  - [x] Reproduction steps
  - [x] evidence_ids (2 or more recommended)
  - [x] promoted (promotion flag)
- [x] DecisionTrace definition
  - [x] decision_type
  - [x] options (choices)
  - [x] selected_option
  - [x] rationale (selection reason)
- [x] Validation functions
  - [x] Required field check
  - [x] Type check
  - [x] evidence_ids existence check
- [x] Unit tests
  - [x] Generation test for each schema
  - [x] Validation tests (normal/abnormal cases)

## Acceptance Criteria

- [x] [AC-5] High/critical level FindingCandidate cannot be generated/promoted unless Evidence requirements are met

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
- schema_version starts from "1.0.0"
- Critical assertions (Findings, etc.) must always be accompanied by evidence_ids
