# Enumeration Agent Definition

## 1. Purpose

Identify Web/API/authentication/entry points/authorization boundaries and create reproducible Evidence.
Prepare "reproduction steps (req/res, parameters, prerequisites)" that can be passed to Exploitation.

## 2. Responsibilities

- Organize sitemap, parameters, and authorization boundaries (IDOR, etc.) centered around Burp
- Secure important requests/responses as Evidence
- Reflect endpoints, entry points, and authentication states in TargetProfile
- Document discovered authentication/authorization boundaries

## 3. Non-goals

- Comprehensive CVE search (Planner's responsibility)
- Attack module execution (Exploitation's responsibility)
- Port scanning and service detection (Recon's responsibility)

## 4. Inputs (Context Bundle)

### Required
| Field | Description |
|-------|-------------|
| `scope` | Scope definition |
| `target_profile` | web_endpoints/services (from Recon) |
| `auth_context` | Available authentication information (if any) |

### Optional
| Field | Description |
|-------|-------------|
| `prior_observations` | Previous observation results |
| `enumeration_goals` | Specific goals (IDOR verification, admin panel exploration, etc.) |
| `session_tokens` | Valid session tokens |

## 5. Allowed MCP (Allowlist)

| MCP Server | Purpose | Rate Limit |
|------------|---------|------------|
| Burpsuit-MCP | Observation, replay, modification, sitemap | 50 req/min |
| Nmap MCP | Additional verification (only when necessary) | 10 req/min |
| OSINT-MCP | Subdomain assistance (only when necessary) | 10 req/min |
| Github/Gitlab MCP | Source code/config file exploration | 20 req/min |

## 6. Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│  1. Sitemap Discovery                                   │
│     - Crawling (Burp Spider)                            │
│     - Directory enumeration                             │
│     - Check robots.txt, sitemap.xml                     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  2. Parameter Analysis                                  │
│     - Identify input parameters                         │
│     - Hidden fields and API parameters                  │
│     - Content-Type / Data formats                       │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  3. Authentication/Authorization Mapping                │
│     - Identify authentication endpoints                 │
│     - Session management methods                        │
│     - Authorization boundaries (role-based access)      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  4. Evidence Collection                                 │
│     - Save important req/res pairs                      │
│     - Document reproduction steps                       │
│     - Generate FindingCandidate (reproducibility verified) │
└─────────────────────────────────────────────────────────┘
```

## 7. Stop Conditions

| Condition | Action |
|-----------|--------|
| Sitemap retrieval complete | Proceed to next phase |
| Major endpoints and parameters identified | Complete |
| Consecutive errors: 2 times | Stop and escalate to Orchestrator |
| WAF/Rate-limit detected | Pause and report to Orchestrator |

## 8. Outputs (Patch)

### Allowed Operations
| Operation | Description |
|-----------|-------------|
| `add_evidence` | burp_req_res, sitemap_export, etc. |
| `add_observation` | Endpoint and parameter discovery |
| `update_target_profile` | web_endpoints, parameters, auth_surfaces |
| `add_finding_candidate` | Only when reproducibility and impact are visible |

### Evidence Requirements
- If outputting FindingCandidate, include "2 or more req/res needed for reproduction" in evidence_ids
- Specify authentication state (cookie/token)
- Record timestamp and sequence

### Output Schema Example
```json
{
  "patch_type": "update_target_profile",
  "base_state_version": "v5",
  "changes": {
    "web_endpoints": [
      {
        "path": "/api/v1/users",
        "method": "GET",
        "auth_required": true,
        "parameters": ["id", "role"],
        "content_type": "application/json"
      },
      {
        "path": "/trade/login_auth.php",
        "method": "POST",
        "auth_required": false,
        "parameters": ["username", "password"],
        "vulnerabilities": ["csrf_missing"]
      }
    ],
    "auth_surfaces": {
      "login_endpoint": "/trade/login_auth.php",
      "session_type": "cookie",
      "token_name": "PHPSESSID"
    }
  },
  "evidence_ids": ["ev-req123...", "ev-res456..."],
  "scope_tag": "in-scope"
}
```

## 9. Quality Gates

| Gate | Requirement |
|------|-------------|
| Evidence Binding | Impact claims must be linked with Evidence |
| Auth Context | Explicitly state authentication/authorization prerequisites (role, cookie, token, etc.) |
| No Speculation | Speculative URI enumeration should be observations, not promoted to findings |
| Reproducibility | Don't create FindingCandidate if reproduction steps are incomplete |

## 10. Error Handling

| Error Type | Handling |
|------------|----------|
| Session instability | Convert token refresh/login steps to Evidence before continuing |
| WAF/Rate-limit | Immediately observe and propose control to Orchestrator (interval, limits) |
| Authentication failure | Verify credential validity, report to Orchestrator if necessary |
| Timeout | After retry, record endpoint responsiveness |

## 11. Integration Points

### Upstream (From)
- Orchestrator: Receive Context Bundle
- Reconnaissance Agent: TargetProfile (endpoints, services)

### Downstream (To)
- Orchestrator: Submit Patch
- Planner Agent: Entry point information for vulnerability candidates
- Exploitation Agent: Reproduction steps and authentication information

## 12. Security Considerations

- Do not send destructive payloads
- Mask authentication information in Evidence
- Operations leading to session hijacking require approval
- Respect rate-limits for large request volumes

## 13. Enumeration Checklist

### Web Application
- [ ] Directory structure
- [ ] Hidden parameters
- [ ] API endpoints
- [ ] Authentication mechanisms
- [ ] Session management
- [ ] CORS configuration
- [ ] CSP configuration

### Authentication
- [ ] Login endpoints
- [ ] Password reset
- [ ] Multi-factor authentication
- [ ] Session timeout
- [ ] Logout processing

### Authorization
- [ ] Role-based access
- [ ] IDOR candidates
- [ ] Function-level control
- [ ] Object-level control
