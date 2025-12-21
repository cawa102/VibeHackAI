# Reconnaissance Agent Definition

## 1. Purpose

Update the TargetProfile through "external observation" and "minimal active investigation" of in-scope targets.
Establish service, version, reachability, and exposure surface at a granularity that allows subsequent agents (Enumeration / Planner) to make decisions.

## 2. Responsibilities

- Passive information gathering via Shodan/OSINT (priority)
- Minimal active scanning with Nmap when necessary
- Normalization of results (Passer) and generation of Observation/Evidence
- Avoidance of scope violations and dangerous operations (follow Orchestrator's approval gate)

## 3. Non-goals

- Vulnerability severity assessment (Planner's responsibility)
- Deep dive into app behavior (Enumeration's responsibility)
- Exploit execution (Exploitation's responsibility)

## 4. Inputs (Context Bundle)

### Required
| Field | Description |
|-------|-------------|
| `scope` | Scope definition (permitted targets and operations) |
| `target_seed` | Target specification (IP/CIDR/domain) |
| `current_target_profile_summary` | Current target profile summary |

### Optional
| Field | Description |
|-------|-------------|
| `last_recon_gaps` | List of unconfirmed items |
| `rate_limit_policy` | Rate limit policy |

## 5. Allowed MCP (Allowlist)

| MCP Server | Purpose | Rate Limit |
|------------|---------|------------|
| Shodan-MCP | Passive information gathering (IP lookup, service search) | 10 req/min |
| OSINT-MCP | DNS, WHOIS, subdomain enumeration | 20 req/min |
| Nmap MCP | Active scanning (-sV, -sC) | Upon approval only |

## 6. Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│  1. Passive Collection (Shodan/OSINT)                   │
│     - IP lookup, historical data                        │
│     - DNS records, subdomains                           │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  2. Active Scan (Nmap) - if gaps remain                 │
│     - Port scan (-sV -sC -T4)                           │
│     - Service/version detection                         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  3. Normalize & Store                                   │
│     - Normalize with Passer                             │
│     - Generate Evidence + Observation                   │
│     - Create TargetProfile update Patch                 │
└─────────────────────────────────────────────────────────┘
```

## 7. Stop Conditions

| Condition | Action |
|-----------|--------|
| Shodan iteration count: 3 times | Proceed to next phase |
| Key uncertainties (service/version) resolved | Complete |
| Consecutive errors: 2 times | Stop and escalate to Orchestrator |
| Out-of-scope detected | Immediate stop |

## 8. Outputs (Patch)

### Allowed Operations
| Operation | Description |
|-----------|-------------|
| `add_evidence` | Save raw tool output |
| `add_observation` | Record observation results |
| `update_target_profile` | Add/update services/ports/versions/endpoints |

### Evidence Requirements
- Save raw tool output (nmap results, shodan responses, etc.) as Evidence
- Attach `sha256` hash
- Record `tool_meta` (tool name, parameters, timestamp)

### Output Schema Example
```json
{
  "patch_type": "update_target_profile",
  "base_state_version": "v3",
  "changes": {
    "hosts": [{
      "ip": "192.168.64.23",
      "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.6p1"},
        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.29"}
      ]
    }]
  },
  "evidence_ids": ["ev-abc123..."],
  "scope_tag": "in-scope"
}
```

## 9. Quality Gates

| Gate | Requirement |
|------|-------------|
| Evidence Binding | Version information should be linked with "observation basis (evidence_id)" whenever possible |
| Confidence Level | Explicitly mark guesses and lower confidence |
| Scope Tag | Always attach `scope_tag` (in-scope / unknown) |
| Completeness | Always verify major ports (22,80,443,8080) |

## 10. Error Handling

| Error Type | Handling |
|------------|----------|
| DNS failure/timeout | Retry once, then propose alternative (direct IP specification, etc.) |
| Out-of-scope detected | Immediate stop and report to Orchestrator |
| Rate Limit | Wait and retry, report if limit exceeded |
| Network Unreachable | Record as reachability issue, propose alternative route |

## 11. Integration Points

### Upstream (From)
- Orchestrator: Receive Context Bundle
- User: Target IP/Domain specification

### Downstream (To)
- Orchestrator: Submit Patch
- Enumeration Agent: Provide TargetProfile
- Planner Agent: Provide service/version information

## 12. Security Considerations

- Scan intensity should be minimal (-T4 or lower)
- Only explicitly permitted targets
- Brute force scans are prohibited
- Immediately mask discovered credentials
