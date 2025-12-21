# 007: Enumeration Agent

## Overview

Implement an Agent that performs detailed investigation of the application layer to understand entry points, authorization boundaries, and attack surface.

## Purpose

- Web application sitemap collection
- Identify entry points (forms, APIs, etc.)
- Understand authentication/authorization boundaries
- Provide detailed data required for subsequent Planner/Exploitation

## Responsibilities

### Areas of Responsibility

- Sitemap/req-res collection via Burpsuite
- Understanding application structure
- Enumeration of entry points and parameters
- Identification of authentication mechanisms

### Not Responsible For

- Vulnerability assessment (performed in Planner)
- Exploit execution (performed in Exploitation)
- Infrastructure layer investigation (performed in Recon)

## MCPs Used

| MCP | Purpose | Priority |
|-----|---------|----------|
| Burpsuite-MCP | Sitemap/req-res collection | High |
| Nmap MCP | Service details (when needed) | Low |
| OSINT-MCP | Known path information (supplementary) | Low |
| GitHub/GitLab MCP | Configuration examples/known paths (supplementary) | Low |

## Input (Context Bundle)

```python
class EnumerationContextBundle:
    session_id: str
    state_version: int
    scope: Scope
    target_profile: TargetProfile  # Includes Recon results
    previous_observations: List[Observation]
```

## Output (Patch)

- `add_evidence`: HTTP req/res, sitemaps, etc.
- `add_observation`: Execution record
- `update_target_profile`: Add entry points, authentication information, etc.

## Processing Flow

1. Extract web services from TargetProfile
2. For each web service:
   a. Get sitemap with Burp → Save Evidence
   b. Enumerate entry points → Update TargetProfile
   c. Identify authentication mechanism → Update TargetProfile
3. Call supplementary MCPs as needed
4. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] Implement EnumerationAgent class
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Burpsuite integration
  - [x] Implement Burpsuite MCP adapter
  - [x] Get sitemap
  - [x] Get req/res pairs
  - [x] Save results as Evidence
  - [x] Convert via Passer
- [x] Entry point analysis
  - [x] Form detection
  - [x] API endpoint detection
  - [x] Parameter enumeration
  - [x] File upload detection
- [x] Authentication analysis
  - [x] Login form detection
  - [x] Session management method identification
  - [x] Authorization boundary estimation
- [x] Supplementary MCP integration
  - [x] Nmap detailed scan (when needed)
  - [ ] OSINT known paths (when needed) - Future implementation
  - [ ] GitHub/GitLab configuration examples (when needed) - Future implementation
- [x] Error handling
  - [x] Retry on MCP failure
  - [x] Timeout processing
  - [x] Processing when authentication required
- [x] Unit tests
  - [x] Burp integration test (mocked)
  - [x] Entry point analysis test
  - [x] Authentication analysis test
  - [x] Patch generation test

## Implementation Completion Notes

**Completion Date**: 2024-12-18

**Test Results**: 105 tests passed (all agent tests)

**Implementation Files**:
- `src/agents/enumeration_agent.py` - EnumerationAgent with full workflow
- `src/mcp_adapters/burp_adapter.py` - BurpAdapter with mock mode
- `tests/agents/test_burp_adapter.py` - 18 tests for Burp adapter
- `tests/agents/test_enumeration_agent.py` - 23 tests for Enumeration agent

**Main Features**:
- Web target extraction (from URLs, domains, target profiles)
- Sitemap collection (spider, get_sitemap)
- Form detection (including login forms, file uploads)
- API endpoint detection (authentication requirements, parameter information)
- Authentication mechanism detection (form_based, session_cookie, api_token)
- Passive scan result collection
- Cookie/header analysis

## Stop Conditions

- Detection of requests to out-of-scope URLs
- Authentication required but no authentication information
- Consecutive MCP failures (2 times)
- Timeout (default 15 minutes)

## Quality Gates

- Evidence of req/res for each entry point
- Completeness of sitemap
- Clear definition of authentication boundaries

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schema)
- 003_passer (normalization)
- 005_orchestrator (caller)
- 006_reconnaissance_agent (previous phase)

## Related Files

```
/src/agents/
  enumeration_agent.py
/src/mcp_adapters/
  burp_adapter.py
```

## Notes

- Crawling depth limited to default 3
- Requests outside same domain prohibited
- Large request volumes may be subject to approval gates
