# 005: Orchestrator (Control Plane)

## Overview

Implements the control plane that connects the Human Interface with Agents, handling approval, sequence control, and state management.

## Purpose

- Interface for tester-system interaction
- Routing and execution control for Agents
- Safety assurance through approval gates
- Centralized State/Evidence management

## Scope

### In Scope

- Human Interface (CLI)
- Agent invocation and routing
- Context Bundle generation
- Approval gates
- Stop condition monitoring
- Patch validation and application (using 004_patch_protocol)

### Out of Scope

- Individual Agent logic (implemented in each Agent ticket)
- Direct MCP calls (through Agents)

## Phase Transitions

```
Recon → Enumeration → Planner → Exploitation → [Post-Exploitation Loop] → Reporting
```

### Rollback Conditions

- Version uncertain → Rollback to Recon
- Insufficient reproduction steps (missing req/res) → Rollback to Enumeration
- Exploit failure due to premise mismatch → Rollback to Planner/Enumeration

### Skip Conditions

- Sufficient evidence from Shodan/OSINT → Nmap scan can be skipped
- No attack surface → Planner proposes stop with "no candidates"

### FR-10: Post-Exploitation Loop (Continuous Test Evaluation)

**Important: Do not immediately transition to report creation after the Exploitation phase ends.**

```
┌────────────────────────────────────────────────────────┐
│              Post-Exploitation Loop                     │
├────────────────────────────────────────────────────────┤
│  1. Orchestrator receives Exploitation results          │
│                        ↓                                │
│  2. Orchestrator provides results to Planner            │
│                        ↓                                │
│  3. Planner thoroughly considers additional tests       │
│                        ↓                                │
│  4. Planner proposes additional test plan to Orchestrator│
│                        ↓                                │
│  5. Orchestrator proposes next phase to human, obtains  │
│     approval                                            │
│                        ↓                                │
│  6. Approved → Execute additional tests (return to 1)   │
│     Rejected/Skipped → Proceed to final report creation │
└────────────────────────────────────────────────────────┘
```

**Termination Conditions (only when all of the following are met):**
1. Planner has considered all additional test items
2. Human explicitly rejected/skipped additional tests
3. Or Planner determines "no further tests available"

## Approval Gate Targets

- Metasploit execution (module execution)
- Payload delivery, persistence-related operations
- High-frequency requests, brute force
- File modification, configuration changes, privilege escalation

## Stop Conditions

- Consecutive error threshold (same error_class 2 times)
- Scope violation detected
- DoS indicators detected
- Unknown destructive behavior

## Implementation Tasks

- [x] CLI implementation
  - [x] Session start/end
  - [x] Scope input and confirmation
  - [x] Phase progress display
  - [x] Approval prompt
  - [x] Result display
- [x] Routing engine
  - [x] Current phase management
  - [x] Next phase determination
  - [x] Rollback determination
  - [x] Skip determination
- [x] Context Bundle generation
  - [x] Extract required information per Agent
  - [x] Attach state_version
  - [x] Minimize (exclude unnecessary information)
- [x] Approval gate
  - [x] requires_approval detection
  - [x] Approval prompt display
  - [x] Approval/rejection recording
  - [x] Timeout handling
- [x] Stop condition monitoring
  - [x] Error count management
  - [x] Scope violation detection
  - [x] Anomalous behavior detection
  - [x] Emergency stop processing
- [x] Patch processing integration
  - [x] Receive Agent response
  - [x] Invoke Patch validation
  - [x] Invoke Patch application
  - [x] Result feedback
- [x] Audit log
  - [x] Record all operations
  - [x] Record approvals/rejections
  - [x] Record phase transitions
- [x] Unit tests
  - [x] Routing tests
  - [x] Context Bundle generation tests
  - [x] Approval gate tests
  - [x] Stop condition tests
- [x] Integration tests
  - [x] Full phase cycle test (mock Agents)
  - [x] Metasploit approval test
  - [x] State/Evidence persistence test
  - [x] Phase rollback test
  - [x] Stop condition test
  - [x] Context Bundle handoff test

## Acceptance Criteria

- [x] [AC-1] Recon→Enumeration→Planner→Exploitation completes a full cycle in minimal case, with State/Evidence saved
- [x] [AC-4] Metasploit execution cannot proceed without approval

## Dependencies

- 001_shared_workspace (State/Evidence management)
- 002_common_schema (schemas)
- 004_patch_protocol (Patch processing)

## Related Files

```
/src/orchestrator/
  __init__.py
  orchestrator.py      # Main Orchestrator class
  router.py           # Phase routing and transitions
  context_builder.py  # Context Bundle generation
  approval_gate.py    # Approval gate for dangerous operations
  stop_monitor.py     # Stop condition monitoring
  audit_logger.py     # Audit logging
/src/cli/
  __init__.py
  cli.py              # Main CLI class
  prompts.py          # User input prompts
  display.py          # Display utilities (colors, tables, etc.)
```

## Notes

- Only Orchestrator writes to State (Single Writer)
- Approval timeout defaults to 5 minutes
- Save State snapshot on emergency stop
