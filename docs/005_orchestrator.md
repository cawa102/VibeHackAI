# 005: Orchestrator (Control Plane)

## Overview

Implements the control plane that connects the Human Interface with Agent groups, responsible for approval, order control, and state management.

## Purpose

- Dialogue interface between tester and system
- Routing and execution control for Agents
- Safety assurance through approval gate
- Centralized management of State/Evidence

## Scope

### In-Scope

- Human Interface (CLI)
- Agent invocation and routing
- Context Bundle generation
- Approval gate
- Stop condition monitoring
- Patch verification and application (using 004_patch_protocol)

### Out-of-Scope

- Individual Agent logic (implemented in each Agent ticket)
- Direct MCP invocation (through Agents)

## Phase Transitions

```
Recon → Enumeration → Planner → Exploitation
```

### Rollback Conditions

- Version undefined → Return to Recon
- Insufficient reproduction procedure (req/res missing) → Return to Enumeration
- Exploit failure due to prerequisite mismatch → Return to Planner/Enumeration

### Skip Conditions

- Sufficient confidence from Shodan/OSINT → Nmap can be omitted
- No attack surface → Planner proposes stop with "no candidates"

## Approval Gate Subjects

- Metasploit execution (module execution)
- Payload delivery, persistence-related operations
- High-frequency requests, brute force
- File modification, configuration changes, privilege escalation

## Stop Conditions

- Consecutive error threshold (same error_class 2 times)
- Scope suspicion detection
- DoS sign detection
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
  - [x] Extract necessary information per Agent
  - [x] Add state_version
  - [x] Minimize (exclude unnecessary information)
- [x] Approval gate
  - [x] Detection of requires_approval
  - [x] Approval prompt display
  - [x] Record approval/rejection
  - [x] Timeout processing
- [x] Stop condition monitoring
  - [x] Error count management
  - [x] Scope violation detection
  - [x] Abnormal behavior detection
  - [x] Emergency stop processing
- [x] Patch processing integration
  - [x] Receive Agent response
  - [x] Call Patch verification
  - [x] Call Patch application
  - [x] Result feedback
- [x] Audit log
  - [x] Record all operations
  - [x] Record approval/rejection
  - [x] Record phase transitions
- [x] Unit tests
  - [x] Routing test
  - [x] Context Bundle generation test
  - [x] Approval gate test
  - [x] Stop condition test
- [x] Integration tests
  - [x] Phase round trip test (mock Agent)
  - [x] Metasploit approval test
  - [x] State/Evidence persistence test
  - [x] Phase rollback test
  - [x] Stop condition test
  - [x] Context Bundle handover test

## Acceptance Criteria

- [x] [AC-1] Recon → Enumeration → Planner → Exploitation completes one round in minimal case, and State/Evidence are saved
- [x] [AC-4] Metasploit execution is not executable without approval

## Dependencies

- 001_shared_workspace (State/Evidence management)
- 002_common_schema (Schema)
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
- Approval timeout default is 5 minutes
- Save State snapshot on emergency stop
