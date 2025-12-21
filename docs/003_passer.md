# 003: Passer (Normalization Engine)

## Overview

Implements an engine that normalizes outputs from each MCP server to common schemas.

## Purpose

- Convert different MCP output formats to unified schemas
- Enable Agent/Orchestrator to work with consistent data structures
- Detect missing or abnormal output

## Scope

### In-Scope

- Definition of normalization rules for each MCP output
- Conversion to TargetProfile/Observation
- Handling of missing and abnormal values

### Out-of-Scope

- MCP invocation itself (implemented in each Adapter)
- State updates (implemented in Patch protocol)

## Supported MCPs

| MCP | Main Output | Conversion Target Schema |
|-----|---------|---------------|
| Nmap | Port scan results | TargetProfile, Observation |
| Shodan | Host information | TargetProfile, Observation |
| OSINT | Domain/organization information | TargetProfile, Observation |
| Burpsuite | HTTP req/res | Observation, EvidenceItem |
| Snyk | Vulnerability information | VulnCandidate |
| CVE-research | CVE details | VulnCandidate |
| GitHub/GitLab | PoC/Exploit information | ExploitCandidate |
| Metasploit | Module execution results | ExecutionResult |
| Kali | Tool execution results | ExecutionResult |

## Implementation Tasks

- [x] Passer foundation implementation
  - [x] Normalization interface definition
  - [x] Automatic MCP type detection
  - [x] Common error handling
- [x] Nmap normalization
  - [x] XML parsing
  - [x] Port/service/OS information extraction
  - [x] TargetProfile conversion
- [x] Shodan normalization
  - [x] JSON response parsing
  - [x] Host/port/banner information extraction
  - [x] TargetProfile conversion
- [x] OSINT normalization
  - [x] Domain information extraction
  - [x] DNS/WHOIS information extraction
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
  - [x] Impact scope/mitigation information extraction
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
  - [x] Test each MCP normalization (normal cases)
  - [x] Missing value handling test
  - [x] Abnormal value handling test

## Acceptance Criteria

- [x] [AC-6] Each MCP output is normalized to common schema by Passer and reflected in TargetProfile/Observation

## Dependencies

- 002_common_schema (conversion target schema)

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
- Unknown fields are retained while issuing warnings (prevent information loss)
- On normalization failure, return partial results instead of error
