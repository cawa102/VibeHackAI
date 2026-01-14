# 006: Reconnaissance Agent

## Overview

Implements an Agent that performs passive OSINT plus minimal active investigation to collect basic target information.

## Purpose

- Collect external exposure information about targets
- Initial identification of ports/services/technology stack
- Provide foundational data for subsequent phases

## Responsibilities

### In Scope

- Passive host information gathering via Shodan
- Domain/organization information gathering via OSINT
- Minimal Nmap scanning when necessary

### Out of Scope

- Detailed application layer investigation (done in Enumeration)
- Vulnerability assessment (done in Planner)
- Exploit execution (done in Exploitation)

## MCP Usage

| MCP | Purpose | Priority |
|-----|---------|----------|
| hexstrike-ai | Host/port/banner info, domain/DNS/WHOIS info, port scanning | High |

## Input (Context Bundle)

```python
class ReconContextBundle:
    session_id: str
    state_version: int
    scope: Scope  # Required
    target_profile: TargetProfile  # Initial state or previous results
    previous_observations: List[Observation]  # Existing observation records
```

## Output (Patch)

- `add_evidence`: Save MCP execution results
- `add_observation`: Execution record
- `update_target_profile`: Add discovered information

## Processing Flow

1. Confirm Scope (get target list)
2. For each target:
   a. Shodan query (passive) → Save Evidence → Update TargetProfile
   b. OSINT query → Save Evidence → Update TargetProfile
   c. Nmap scan if necessary → Save Evidence → Update TargetProfile
3. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] ReconAgent class implementation
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Shodan integration
  - [x] Shodan MCP adapter implementation
  - [x] Host information retrieval
  - [x] Evidence storage of results
  - [x] TargetProfile conversion via Passer
- [x] OSINT integration
  - [x] OSINT MCP adapter implementation
  - [x] Domain/DNS information retrieval
  - [x] Evidence storage of results
  - [x] TargetProfile conversion via Passer
- [x] Nmap integration
  - [x] Nmap MCP adapter implementation
  - [x] Scan execution (minimal ports)
  - [x] Evidence storage of results
  - [x] TargetProfile conversion via Passer
- [x] Skip determination
  - [x] Skip Nmap when Shodan/OSINT is sufficient
  - [x] Record skip reason in DecisionTrace
- [x] Error handling
  - [x] Retry on MCP failure
  - [x] Timeout handling
  - [x] Partial success handling
- [x] Unit tests
  - [x] Each MCP integration test (mock)
  - [x] Patch generation test
  - [x] Skip determination test
  - [x] Error handling test

## Implementation Completion Notes

**Completion Date**: 2024-12-18

**Test Results**: 64 tests passed

**Implementation Files**:
- `src/agents/__init__.py` - Agent exports
- `src/agents/base_agent.py` - BaseAgent, AgentConfig, AgentContext, AgentOutput, DecisionTrace
- `src/agents/reconnaissance_agent.py` - ReconnaissanceAgent with full workflow
- `src/mcp_adapters/__init__.py` - MCP adapter exports
- `src/mcp_adapters/base_adapter.py` - BaseMCPAdapter, MCPResult, MCPError, MCPToolType
- `src/mcp_adapters/shodan_adapter.py` - ShodanAdapter with mock mode
- `src/mcp_adapters/osint_adapter.py` - OSINTAdapter with mock mode
- `src/mcp_adapters/nmap_adapter.py` - NmapAdapter with mock mode
- `tests/agents/__init__.py`
- `tests/agents/test_base_agent.py` - 18 tests for base agent classes
- `tests/agents/test_mcp_adapters.py` - 32 tests for MCP adapters
- `tests/agents/test_reconnaissance_agent.py` - 14 tests for reconnaissance agent

## Stop Conditions

- Out-of-scope target detected
- Consecutive MCP failures (2 times)
- Timeout (default 10 minutes)

## Quality Gates

- At least one Evidence accompanying TargetProfile update
- Completeness of Observation records

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schemas)
- 003_passer (normalization)
- 005_orchestrator (caller)

## Related Files

```
/src/agents/
  __init__.py
  base_agent.py
  reconnaissance_agent.py
/src/mcp_adapters/
  shodan_adapter.py
  osint_adapter.py
  nmap_adapter.py
```

## Notes

- Nmap runs at `-T2` or lower speed (stealth priority)
- Large CIDRs (/16 or larger) suggest sampling
- Prioritize passive investigation, minimize active scanning
