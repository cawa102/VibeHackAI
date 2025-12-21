# 006: Reconnaissance Agent

## Overview

Implement an Agent that performs passive OSINT + minimum necessary active investigation to collect basic information about targets.

## Purpose

- Collect externally exposed information about targets
- Initial grasp of ports/services/technology stack
- Provide basic data required for subsequent phases

## Responsibilities

### Areas of Responsibility

- Passive host information collection via Shodan
- Domain/organization information collection via OSINT
- Minimum necessary Nmap scanning

### Not Responsible For

- Detailed investigation of application layer (performed in Enumeration)
- Vulnerability assessment (performed in Planner)
- Exploit execution (performed in Exploitation)

## MCPs Used

| MCP | Purpose | Priority |
|-----|---------|----------|
| Shodan-MCP | Host/port/banner information (passive) | High |
| OSINT-MCP | Domain/DNS/WHOIS information | High |
| Nmap MCP | Port scanning (active) | Medium |

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

1. Confirm Scope (obtain target list)
2. For each target:
   a. Shodan query (passive) → Save Evidence → Update TargetProfile
   b. OSINT query → Save Evidence → Update TargetProfile
   c. Nmap scan if necessary → Save Evidence → Update TargetProfile
3. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] Implement ReconAgent class
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Shodan integration
  - [x] Implement Shodan MCP adapter
  - [x] Host information acquisition
  - [x] Save results as Evidence
  - [x] TargetProfile conversion via Passer
- [x] OSINT integration
  - [x] Implement OSINT MCP adapter
  - [x] Domain/DNS information acquisition
  - [x] Save results as Evidence
  - [x] TargetProfile conversion via Passer
- [x] Nmap integration
  - [x] Implement Nmap MCP adapter
  - [x] Execute scan (minimal ports)
  - [x] Save results as Evidence
  - [x] TargetProfile conversion via Passer
- [x] Skip determination
  - [x] Skip Nmap when Shodan/OSINT sufficient
  - [x] Record skip reason in DecisionTrace
- [x] Error handling
  - [x] Retry on MCP failure
  - [x] Timeout processing
  - [x] Partial success handling
- [x] Unit tests
  - [x] Test each MCP integration (mocked)
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

- Detection of out-of-scope targets
- Consecutive MCP failures (2 times)
- Timeout (default 10 minutes)

## Quality Gates

- TargetProfile update with at least 1 Evidence
- Completeness of Observation records

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schema)
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

- Execute Nmap at `-T2` or lower speed (stealth priority)
- Suggest sampling for large CIDRs (/16 or larger)
- Prioritize passive investigation, minimize active scanning
