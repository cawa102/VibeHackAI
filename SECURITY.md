# Security Policy

## Responsible Use

PentestAgent is a powerful security testing tool. **You must use it responsibly and ethically.**

### Authorized Use Only

This tool is intended **exclusively** for:

- **Authorized penetration testing** with written permission
- **Security research** on systems you own or have explicit authorization to test
- **CTF (Capture The Flag) competitions** and security challenges
- **Educational purposes** in controlled lab environments
- **Defensive security** to test your own systems

### Prohibited Use

**DO NOT** use PentestAgent for:

- Unauthorized access to systems you don't own
- Testing systems without explicit written permission
- Denial of Service (DoS) attacks
- Mass scanning or targeting
- Any illegal activities
- Malicious purposes of any kind

### Legal Compliance

Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Following responsible disclosure practices
- Documenting authorization and scope

## Security Features

PentestAgent includes built-in safety mechanisms:

### Scope Enforcement

- All operations are scope-tagged
- Out-of-scope targets are automatically blocked
- Scope violations trigger immediate stop

### Approval Gates

The following operations require explicit human approval:

- Metasploit module execution
- Payload delivery or persistence
- Brute force or high-frequency requests
- Privilege escalation attempts
- Any potentially destructive operations

### Automatic Stop Conditions

- Consecutive errors (potential scope violation)
- DoS pattern detection
- Unknown destructive behavior
- Scope suspicion triggers

### Evidence Integrity

- Append-only evidence storage
- SHA256 hash verification
- Complete audit trails
- Tamper-resistant logging

## Reporting Security Vulnerabilities

### Scope

We welcome security reports for:

- Vulnerabilities in PentestAgent code
- Security issues in our build/release process
- Flaws in safety mechanisms
- Authentication/authorization bypasses

### Out of Scope

- Vulnerabilities in third-party MCP servers
- Issues in external tools (Metasploit, Nmap, etc.)
- Social engineering attacks
- Physical security

### How to Report

1. **Email**: security@example.com (replace with actual contact)
2. **Subject**: [SECURITY] Brief description

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Safe Harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations
- Avoid data destruction
- Report vulnerabilities responsibly
- Give us reasonable time to respond

## Disclosure Policy

### Private Disclosure

Please report vulnerabilities privately first. Do not:

- Disclose publicly before resolution
- Exploit vulnerabilities beyond proof-of-concept
- Access or modify user data

### Credit

We will credit researchers (with permission) in:

- Release notes
- Security advisories
- Hall of Fame (if applicable)

## Security Best Practices

### For Users

1. **Keep updated**: Use the latest version
2. **Secure API keys**: Never commit keys to repositories
3. **Limit scope**: Define minimal necessary scope
4. **Review approvals**: Carefully review before approving actions
5. **Audit logs**: Regularly review audit logs
6. **Isolated environment**: Run in isolated networks when testing

### For Contributors

1. **No hardcoded secrets**: Use environment variables
2. **Input validation**: Validate all external input
3. **Output sanitization**: Mask sensitive data in logs
4. **Least privilege**: Request minimal permissions
5. **Security review**: Consider security implications of changes

## Audit and Compliance

### Logging

PentestAgent maintains comprehensive logs:

- All MCP operations
- Approval decisions
- State changes
- Evidence collection

### Export

Logs can be exported for:

- Compliance audits
- Incident investigation
- Report generation

## Contact

- **Security Issues**: security@example.com
- **General Questions**: Open a GitHub issue
- **Urgent Issues**: Include [URGENT] in subject

---

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE, DAMAGE, OR ILLEGAL ACTIVITIES CONDUCTED WITH THIS TOOL.

By using PentestAgent, you acknowledge that:

1. You will only test systems you own or have authorization to test
2. You will comply with all applicable laws
3. You accept full responsibility for your actions
4. The authors are not liable for any consequences of use

**When in doubt, don't test. Get explicit written authorization first.**
