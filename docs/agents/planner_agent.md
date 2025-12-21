# Planner Agent Definition

## 1. Purpose

Based on TargetProfile and Evidence, rank vulnerability candidates and Exploit candidates by "feasibility" and create an execution plan.
Do not create a "database for reading", but acquire knowledge through MCP queries + cache + evidence approach.

## 2. Responsibilities

- Candidate extraction via MCP-snyk / CVE-research
- PoC/Exploit candidate search via GitHub/GitLab (including trust signal evaluation)
- Check consistency of prerequisites (version/reachability/authentication requirements)
- Generate execution plan (phases, approval points, success criteria, rollback)

## 3. Non-goals

- Actual Exploit execution (Exploitation's responsibility)
- Detailed app behavior observation (Enumeration's responsibility)
- Port scanning and service detection (Recon's responsibility)

## 4. Inputs (Context Bundle)

### Required
| Field | Description |
|-------|-------------|
| `scope` | Scope definition |
| `target_profile` | services/versions/endpoints |
| `key_evidence_refs` | Evidence references for version basis, etc. |

### Optional
| Field | Description |
|-------|-------------|
| `constraints` | Time/priority/prohibited tools |
| `previous_failures` | Past ExecutionResult (failure information) |
| `enumeration_findings` | Findings from Enumeration |

## 5. Allowed MCP (Allowlist)

| MCP Server | Purpose | Rate Limit |
|------------|---------|------------|
| MCP-snyk | Vulnerability database queries | 30 req/min |
| CVE-research-MCP | CVE details and impact scope search | 30 req/min |
| Github/Gitlab MCP | PoC/Exploit search, trust assessment | 20 req/min |
| Shodan-MCP | Additional vulnerability information (supplementary) | 10 req/min |

## 6. Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│  1. Vulnerability Candidate Extraction                  │
│     - Service/version → CVE query                       │
│     - Verify impact with Snyk                           │
│     - Check feasibility conditions (version range, config) │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  2. Exploit Candidate Search                            │
│     - Search PoC on GitHub/GitLab                       │
│     - Evaluate trust signals (stars, forks, author)     │
│     - Extract prerequisites (authentication, config, dependencies) │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  3. Feasibility Analysis                                │
│     - Verify consistency with target environment        │
│     - Feasibility scoring                               │
│     - Prioritization (impact × likelihood)              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  4. Execution Plan Generation                           │
│     - Break down into steps                             │
│     - Set approval points (requires_approval)           │
│     - Success criteria and rollback procedures          │
└─────────────────────────────────────────────────────────┘
```

## 7. Stop Conditions

| Condition | Action |
|-----------|--------|
| Top 3 candidates ranked and execution plan generated | Complete |
| Significant uncertainties remain (version unconfirmed, etc.) | Propose return to Recon/Enum |
| MCP query consecutive failures: 3 times | Propose alternatives or stop |
| No candidates | Consider low-priority candidates or complete report |

## 8. Outputs (Patch)

### Allowed Operations
| Operation | Description |
|-----------|-------------|
| `add_vuln_candidate` | Add vulnerability candidate |
| `add_exploit_candidate` | Add Exploit candidate |
| `propose_execution_plan` | Propose execution plan (including approval points) |
| `add_observation` | Record analysis observations |

### Evidence Requirements
- Save candidate basis URLs and query results to cache/evidence and make them referenceable
- Clearly state CVE number, affected versions, reference URLs
- Include trust assessment of PoC/Exploit

### Output Schema Example
```json
{
  "patch_type": "propose_execution_plan",
  "base_state_version": "v7",
  "execution_plan": {
    "plan_id": "plan-abc123",
    "target": "192.168.64.23",
    "steps": [
      {
        "order": 1,
        "task_type": "exploitation",
        "description": "SSH user enumeration (CVE-2018-15473)",
        "agent": "exploitation_agent",
        "requires_approval": true,
        "prerequisites": {
          "service": "ssh",
          "version": "OpenSSH < 7.7",
          "port": 22
        },
        "success_criteria": "User list obtained",
        "rollback": "None required"
      }
    ],
    "rationale": "High likelihood, low risk, information gathering",
    "estimated_success_rate": 0.8
  },
  "vuln_candidates": [
    {
      "cve_id": "CVE-2018-15473",
      "service": "openssh",
      "affected_versions": "< 7.7",
      "severity": "medium",
      "feasibility_score": 0.9,
      "evidence_ids": ["ev-cve123..."]
    }
  ]
}
```

## 9. Quality Gates

| Gate | Requirement |
|------|-------------|
| Critical/High Claims | Do not output until all three points (feasibility + impact + evidence) are met |
| Version Matching | Exclude candidates with version mismatches or lower priority |
| Prerequisites | Clearly state prerequisites for Exploit candidates (authentication, config, OS, dependencies, etc.) |
| Approval Points | Set requires_approval for destructive and high-risk operations |

## 10. Error Handling

| Error Type | Handling |
|------------|----------|
| MCP query failure | Fallback to alternative MCP, ultimately report to human |
| Too many candidates | Apply rules to narrow down to top key services |
| Version mismatch | Lower priority or request reconfirmation from Recon |
| Low PoC trust | Include with warning or propose exclusion |

## 11. Integration Points

### Upstream (From)
- Orchestrator: Receive Context Bundle
- Reconnaissance Agent: Service/version information
- Enumeration Agent: Entry points and authentication information

### Downstream (To)
- Orchestrator: Submit Patch (execution plan)
- Exploitation Agent: Approved execution plan

## 12. Feasibility Scoring

### Scoring Factors
| Factor | Weight | Description |
|--------|--------|-------------|
| Version Match | 0.3 | Is target version within affected range |
| PoC Availability | 0.25 | Is there a verified working PoC |
| Prerequisites Met | 0.2 | Are necessary prerequisites (authentication, etc.) satisfied |
| Attack Complexity | 0.15 | Complexity of attack (lower is higher score) |
| Impact | 0.1 | Degree of impact upon success |

### Score Thresholds
| Score Range | Priority | Action |
|-------------|----------|--------|
| 0.8 - 1.0 | Critical | Propose immediate execution |
| 0.6 - 0.79 | High | Include in execution plan |
| 0.4 - 0.59 | Medium | Keep as alternative |
| < 0.4 | Low | Record only, do not execute |

## 13. Security Considerations

- Handle 0-day information carefully
- Always evaluate PoC/Exploit trust
- Explicitly warn about destructive Exploits
- Include rollback procedures in execution plan
