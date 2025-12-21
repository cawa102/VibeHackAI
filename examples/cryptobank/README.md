# CryptoBank Penetration Test: Human vs AI Comparison

This directory contains two penetration test reports for the same target (CryptoBank VM) — one conducted manually by a human tester, and one conducted with VibeHackAI assistance.

## Target

- **VM:** CryptoBank (cryptocurrency trading platform)
- **IP:** 192.168.64.23
- **Services:** Apache 2.4.29, PHP 7.2.24, MySQL 5.7.42, OpenSSH 7.6p1, Apache Solr 8.1.1

## Reports

| Report | Tester | Format | Description |
|--------|--------|--------|-------------|
| [manual_report.pdf](manual_report.pdf) | Human (Kyosuke Kawai) | PDF | Professional pentest report with detailed methodology, CVSS v4.0 scoring, and comprehensive evidence |
| [ai_report.md](ai_report.md) | VibeHackAI | Markdown | AI-assisted report with structured findings and attack chain documentation |

## Comparison Summary

### Findings Coverage

| Finding | Human Report | AI Report |
|---------|--------------|-----------|
| SQL Injection (login bypass + data extraction) | F-01 (Critical) | #1 (Critical) |
| Exposed Development Interfaces | F-02 (High) | #10 (Medium) |
| Weak/Reused Credentials | F-03 (High) | #3 (Critical) |
| Remote Command Execution | F-04 (Critical) | N/A (used File Upload path) |
| Apache Solr RCE + Privilege Escalation | F-05 (Critical) | N/A |
| WAF Password Reset Vulnerability | F-06 (High) | N/A |
| Unrestricted File Upload | N/A (part of F-04) | #2 (Critical) |
| PHPInfo Disclosure | Mentioned | #4 (High) |
| Plaintext Password Storage | Mentioned | #5 (High) |
| Missing CSRF | Mentioned | #6 (High) |
| Session Management Issues | Mentioned | #7 (High) |

### Key Differences

| Aspect | Human Report | AI Report |
|--------|--------------|-----------|
| **Attack Depth** | Achieved root via Solr container | Achieved www-data via file upload |
| **Methodology** | PTES/OWASP structured, test coverage matrix | Phase-based (Recon → Exploit) |
| **CVSS Version** | v4.0 with detailed vectors | v3.1 style scores |
| **Evidence** | Screenshots with terminal output | Code snippets and commands |
| **Recommendations** | Business-focused, prioritized | Technical fixes with code examples |

### What the Human Found That AI Missed

1. **Apache Solr RCE (CVE-2019-17558)** — The human tester discovered the internal Solr service on the Docker network (172.17.0.1:8983) and exploited it to gain root access
2. **NinjaFirewall Password Reset** — Unauthenticated password change vulnerability
3. **Sudo Privilege Escalation** — The solr user had `(ALL) NOPASSWD: ALL` sudo rights

### What AI Found That Human Covered Differently

1. **File Upload as Primary RCE Path** — AI used .phtml upload with GIF header bypass as the main exploitation path
2. **More Detailed Credential Extraction** — AI documented all 12 extracted credentials explicitly

## Observations

### Human Advantages
- **Deeper enumeration**: Found internal Docker services and container escape paths
- **Business context**: Recommendations tied to organizational risk
- **Lateral thinking**: Discovered non-obvious attack chains (Solr → sudo → root)

### AI Advantages
- **Speed**: Faster initial reconnaissance and vulnerability identification
- **Consistency**: Structured output format with reproducible steps
- **Documentation**: Clear proof-of-concept commands ready for verification

## Conclusion

This comparison demonstrates how **human expertise and AI assistance complement each other**:

- The human tester achieved deeper compromise (root access) through lateral movement and container exploitation
- The AI-assisted test provided rapid initial assessment with clear documentation
- Together, they would provide more comprehensive coverage than either alone

This is exactly what VibeHackAI is designed for: **combining AI speed with human judgment** for more effective penetration testing.
