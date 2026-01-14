# 001: Shared Workspace + Evidence Ledger

## Overview

Implements a session data persistence layer and tamper-resistant storage mechanism for Evidence.

## Purpose

- Manage State/Evidence/Cache on a per-session basis
- Append-only Evidence storage with sha256 hash integrity guarantee
- Integration with Filesystem MCP

## Scope

### In Scope

- Session directory structure creation and management
- Evidence Ledger (append-only, with sha256)
- Basic CRUD operations for State/Evidence/Cache
- Filesystem MCP integration

### Out of Scope

- State update logic (implemented in Patch Protocol)
- Normalization processing (implemented in Passer)

## Directory Structure

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

## Acceptance Criteria

- [x] [AC-2] Evidence is stored with sha256 in append-only manner and can be referenced from State

## Notes

- When storing Evidence, always record timestamp, source_tool, query_params, response_code in meta.json
- Consider split storage for large outputs (>10MB)
