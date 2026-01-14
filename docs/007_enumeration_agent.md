# 007: Enumeration Agent

## Overview

Implements an Agent that performs detailed application layer investigation to understand entry points, authorization boundaries, and attack surfaces.

## Purpose

- Collect web application sitemaps
- Identify entry points (forms, APIs, etc.)
- Understand authentication/authorization boundaries
- Provide detailed data needed for Planner/Exploitation

## Responsibilities

### In Scope

- Sitemap/request-response collection via Burpsuite
- Understanding application structure
- Enumeration of entry points and parameters
- Identification of authentication mechanisms

### Out of Scope

- Vulnerability assessment (done in Planner)
- Exploit execution (done in Exploitation)
- Infrastructure layer investigation (done in Recon)

## MCP Usage

| MCP | Purpose | Priority |
|-----|---------|----------|
| hexstrike-ai | Sitemap/req-res collection, service details, known path information | High |
| GitHub | Configuration examples/known paths (auxiliary) | Low |

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
- `update_target_profile`: Add entry points, authentication info, etc.

## Processing Flow

1. Extract web services from TargetProfile
2. For each web service:
   a. Get sitemap with Burp → Save Evidence
   b. Enumerate entry points → Update TargetProfile
   c. Identify authentication mechanism → Update TargetProfile
3. Call auxiliary MCPs as needed
4. Generate and return Patch

## Implementation Tasks

- [x] Agent foundation
  - [x] EnumerationAgent class implementation
  - [x] Context Bundle reception processing
  - [x] Patch generation processing
- [x] Burpsuite integration
  - [x] Burpsuite MCP adapter implementation
  - [x] Sitemap retrieval
  - [x] Request/response pair retrieval
  - [x] Evidence storage of results
  - [x] Conversion via Passer
- [x] Entry point analysis
  - [x] Form detection
  - [x] API endpoint detection
  - [x] Parameter enumeration
  - [x] File upload detection
- [x] Authentication analysis
  - [x] Login form detection
  - [x] Session management method identification
  - [x] Authorization boundary estimation
- [x] Auxiliary MCP integration
  - [x] Nmap detailed scan (when needed)
  - [ ] OSINT known paths (when needed) - Future implementation
  - [ ] GitHub/GitLab configuration examples (when needed) - Future implementation
- [x] Error handling
  - [x] Retry on MCP failure
  - [x] Timeout handling
  - [x] Authentication required handling
- [x] Unit tests
  - [x] Burp integration test (mock)
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
- Web target extraction (from URL, domain, target profile)
- Sitemap collection (spider, get_sitemap)
- Form detection (including login forms, file uploads)
- API endpoint detection (authentication requirements, parameter information)
- Authentication mechanism detection (form_based, session_cookie, api_token)
- Passive scan results collection
- Cookie/header analysis

## Stop Conditions

- Out-of-scope URL request detected
- Authentication required but no credentials
- Consecutive MCP failures (2 times)
- Timeout (default 15 minutes)

## Quality Gates

- req/res Evidence for each entry point
- Sitemap completeness
- Clear authentication boundary definition

## Dependencies

- 001_shared_workspace (Evidence storage)
- 002_common_schema (schemas)
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

- Crawling depth limited to 3 by default
- Requests outside the same domain are prohibited
- High-volume requests may be subject to approval gate
