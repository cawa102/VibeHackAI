**This document provides evaluation criteria based on CVSS 3.1**

---

## CVSS Evaluation Guidelines

### CVSS 3.1 Evaluation Guide

| Metric | Evaluation Question | Values |
|--------|---------------------|--------|
| Attack Vector (AV) | Where is the attack originating from? | N=Network, A=Adjacent, L=Local, P=Physical |
| Attack Complexity (AC) | Are special conditions required? | L=Low, H=High |
| Privileges Required (PR) | Is authentication required? | N=None, L=Low, H=High |
| User Interaction (UI) | Is user action required? | N=None, R=Required |
| Scope (S) | Does the impact scope change? | U=Unchanged, C=Changed |
| Confidentiality (C) | Impact on confidentiality | N=None, L=Low, H=High |
| Integrity (I) | Impact on integrity | N=None, L=Low, H=High |
| Availability (A) | Impact on availability | N=None, L=Low, H=High |

### Severity Scale

| Base Score | Severity | Response Priority |
|------------|----------|-------------------|
| 9.0 - 10.0 | Critical | Immediate response, highest priority |
| 7.0 - 8.9 | High | Priority response |
| 4.0 - 6.9 | Medium | Planned response |
| 0.1 - 3.9 | Low | Address when opportunity arises |

---

## Feasibility Scoring

### Score Calculation Formula

```
Feasibility Score =
    (Version Match × 0.30) +
    (PoC Availability × 0.25) +
    (Prerequisites Met × 0.20) +
    (Attack Complexity Inverse × 0.15) +
    (Impact × 0.10)
```

### Evaluation Criteria for Each Factor

| Factor | 1.0 | 0.7 | 0.4 | 0.0 |
|--------|-----|-----|-----|-----|
| Version Match | Exact match | Within range | Close version | Out of range |
| PoC Availability | Verified working PoC | Unverified PoC | Proof of concept only | None |
| Prerequisites Met | All met | Mostly met | Partially met | Not met |
| Attack Complexity | Automatable | Manually easy | Expert knowledge required | Very difficult |
| Impact | Critical | High | Medium | Low |

### Priority Thresholds

| Score Range | Priority | Action |
|-------------|----------|--------|
| 0.80 - 1.00 | Critical | Create ExecutionPlan immediately |
| 0.60 - 0.79 | High | Include in ExecutionPlan |
| 0.40 - 0.59 | Medium | Hold as alternative |
| 0.00 - 0.39 | Low | Record only |
