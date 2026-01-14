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

## Implementation Tasks

- [x] Passer foundation implementation
  - [x] Normalization interface definition
  - [x] Automatic MCP type detection
  - [x] Common error handling
- [x] Nmap normalization
  - [x] XML parsing
  - [x] Port/service/OS info extraction
  - [x] TargetProfile conversion
- [x] Shodan normalization
  - [x] JSON response parsing
  - [x] Host/port/banner info extraction
  - [x] TargetProfile conversion
- [x] OSINT normalization
  - [x] Domain info extraction
  - [x] DNS/WHOIS info extraction
  - [x] TargetProfile conversion
- [x] Burpsuite normalization
  - [x] Sitemap analysis
  - [x] req/res pair extraction
  - [x] Observation/Evidence conversion
- [x] Snyk normalization
  - [x] Vulnerability list analysis
  - [x] CVSS/severity mapping
  - [x] VulnCandidate conversion
- [x] CVE-research normalization
  - [x] CVE detail analysis
  - [x] Impact scope/remediation info extraction
  - [x] VulnCandidate conversion
- [x] GitHub/GitLab normalization
  - [x] Repository/code search result analysis
  - [x] PoC/Exploit candidate extraction
  - [x] ExploitCandidate conversion
- [x] Metasploit normalization
  - [x] Session/execution result analysis
  - [x] Success/failure determination
  - [x] ExecutionResult conversion
- [x] Kali normalization
  - [x] Command output analysis
  - [x] ExecutionResult conversion
- [x] Unit tests
  - [x] Each MCP normalization test (normal cases)
  - [x] Missing value handling tests
  - [x] Anomalous value handling tests

## Acceptance Criteria

- [x] [AC-6] Each MCP output is normalized by Passer into common schema and reflected in TargetProfile/Observation

## Dependencies

- 002_common_schema (target schemas)

## Related Files

```
/src/passer/
  __init__.py
  base.py
  nmap_passer.py
  shodan_passer.py
  osint_passer.py
  burp_passer.py
  snyk_passer.py
  cve_passer.py
  github_passer.py
  msf_passer.py
  kali_passer.py

/tests/passer/
  __init__.py
  test_base.py
  test_nmap_passer.py
  test_shodan_passer.py
  test_snyk_passer.py
  test_github_passer.py
  test_msf_passer.py
  test_kali_passer.py
```

## Notes

- Each Passer can be added in plugin format
- Unknown fields are preserved with warnings (prevent info loss)
- On normalization failure, return partial results instead of errors
