# 003: Passer (Normalization Engine)

## Overview

Implements an engine to normalize outputs from various MCP servers into common schemas.

## Purpose

- Convert different MCP output formats into unified schemas
- Enable Agent/Orchestrator to handle consistent data structures
- Detect missing or anomalous output data

## Scope

### In Scope

- Define normalization rules for each MCP output
- Convert to TargetProfile/Observation
- Handle missing and anomalous values

### Out of Scope

- MCP calls themselves (implemented in each Adapter)
- State updates (implemented in Patch Protocol)

## Supported MCPs

| MCP | Primary Output | Target Schema |
|-----|----------------|---------------|
| filesystem | File management | filesystem operations |
| GitHub | PoC/Exploit info | ExploitCandidate |
| hexstrike-ai | Tool execution results | ExecutionResult |

## Acceptance Criteria

- [x] [AC-6] Each MCP output is normalized by Passer into common schema and reflected in TargetProfile/Observation

## Dependencies

- 002_common_schema (target schemas)

## Notes

- Each Passer can be added in plugin format
- Unknown fields are preserved with warnings (prevent info loss)
- On normalization failure, return partial results instead of errors
