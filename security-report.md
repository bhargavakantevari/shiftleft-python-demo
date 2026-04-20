# Security Audit Report

**Project:** flask-webgoat  
**Date:** 2026-04-20  
**Auditor:** Factory AI Security Audit

---

## Executive Summary

This security audit was performed on the flask-webgoat project, a deliberately vulnerable Flask web application designed for security training. The audit identified **critical vulnerabilities** in both the application code and its dependencies. This report documents all findings and provides recommendations for remediation.

⚠️ **IMPORTANT NOTE:** This application is intentionally vulnerable for educational purposes. The vulnerabilities documented below are features of the WebGoat training application, not bugs.

---

## Table of Contents

1. [Dependency Vulnerabilities](#1-dependency-vulnerabilities)
2. [Hardcoded Secrets & Sensitive Data Exposure](#2-hardcoded-secrets--sensitive-data-exposure)
3. [SQL Injection Vulnerabilities](#3-sql-injection-vulnerabilities)
4. [Remote Code Execution (RCE)](#4-remote-code-execution-rce)
5. [Insecure Deserialization](#5-insecure-deserialization)
6. [Directory Traversal](#6-directory-traversal)
7. [Open Redirect](#7-open-redirect)
8. [Broken Access Control](#8-broken-access-control)
9. [Security Misconfiguration](#9-security-misconfiguration)
10. [Authentication & Authorization Issues](#10-authentication--authorization-issues)
11. [XSS Vulnerabilities](#11-xss-vulnerabilities)
12. [Remediation Summary](#12-remediation-summary)

---

## 1. Dependency Vulnerabilities

### Status: ✅ FIXED

### Findings

The original `requirements.txt` contained severely outdated packages with multiple known CVEs:

| Package | Old Version | CVEs/Vulnerabilities | Fixed Version |
|---------|-------------|---------------------|---------------|
| Flask | 0.12.5 | 6 total vulnerabilities | 3.1.3 |
| Jinja2 | 2.8 | 10 total vulnerabilities (including XSS CVE-2024-22195) | 3.1.6 |
| Werkzeug | 0.16.1 | 9 vulnerabilities (including HIGH severity RCE, DoS) | 3.1.8 |
| click | 7.1.2 | Outdated | 8.1.7 |
| itsdangerous | 1.1.0 | Outdated | 2.2.0 |
| MarkupSafe | 1.1.1 | Outdated | 2.1.5 |

### Critical Werkzeug Vulnerabilities (0.16.1):
- **HIGH - Remote Code Execution (RCE)** - CVE in debugger allowing code execution
- **HIGH - Denial of Service (DoS)** - Multipart form data parsing resource exhaustion
- **MEDIUM - Directory Traversal** - `safe_join()` bypass on Windows
- **MEDIUM - Resource Exhaustion** - Multipart parser memory consumption
- **LOW - Access Restriction Bypass** - Nameless cookie parsing

### Critical Jinja2 Vulnerabilities (2.8):
- **MEDIUM - XSS (CVE-2024-22195)** - Cross-site scripting vulnerability
- Multiple sandbox escape and path traversal vulnerabilities

### Remediation Applied
Updated `requirements.txt` to use secure versions:
```
click>=8.1.7
Flask>=3.1.3
itsdangerous>=2.2.0
Jinja2>=3.1.6
MarkupSafe>=2.1.5
Werkzeug>=3.1.8
```

---

## 2. Hardcoded Secrets & Sensitive Data Exposure

### Status: ⚠️ CRITICAL - REQUIRES MANUAL FIX

### Finding 2.1: Hardcoded Secret Key
**File:** `flask_webgoat/__init__.py` (Line 22)
**Severity:** CRITICAL

```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```

**Risk:** Session cookies can be forged by attackers who know this key, leading to session hijacking and authentication bypass.

**Recommendation:**
```python
import os
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
```

### Finding 2.2: Hardcoded Admin Credentials
**File:** `flask_webgoat/__init__.py` (Lines 33-34)
**Severity:** CRITICAL

```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

**Risk:** Default credentials are publicly known and stored in plaintext.

**Recommendation:**
- Use environment variables for initial admin credentials
- Hash passwords using bcrypt or argon2
- Implement first-run setup wizard

### Finding 2.3: SQL Trace Callback Exposing Data
**File:** `flask_webgoat/__init__.py` (Line 13)
**Severity:** MEDIUM

```python
conn.set_trace_callback(print)
```

**Risk:** All SQL queries including credentials are printed to stdout/logs.

**Recommendation:** Remove trace callback in production or use proper logging with sensitive data masking.

### Finding 2.4: Passwords Stored in Plaintext
**File:** Database schema  
**Severity:** CRITICAL

Passwords are stored as plaintext in the `user` table.

**Recommendation:** Use password hashing (bcrypt, argon2, or scrypt).

---

## 3. SQL Injection Vulnerabilities

### Status: ⚠️ CRITICAL - REQUIRES MANUAL FIX

### Finding 3.1: Login SQL Injection
**File:** `flask_webgoat/auth.py` (Lines 17-21)
**Severity:** CRITICAL

```python
# vulnerability: SQL Injection
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```

**Attack Vector:** `' OR '1'='1' --`

**Impact:** Complete authentication bypass, data exfiltration.

**Secure Implementation:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

### Finding 3.2: User Creation SQL Injection
**File:** `flask_webgoat/users.py` (Lines 37-41)
**Severity:** CRITICAL

```python
# vulnerability: SQL Injection
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

**Impact:** Arbitrary user creation, privilege escalation, data manipulation.

**Secure Implementation:**
```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, password, int(access_level)), False, True)
```

---

## 4. Remote Code Execution (RCE)

### Status: ⚠️ CRITICAL - REQUIRES MANUAL FIX

### Finding 4.1: Command Injection
**File:** `flask_webgoat/actions.py` (Lines 43-49)
**Severity:** CRITICAL

```python
# vulnerability: Remote Code Execution
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

**Attack Vector:** `; cat /etc/passwd #` or `$(whoami)` or `` `id` ``

**Impact:** Full system compromise, arbitrary command execution.

**Secure Implementation:**
```python
import shlex

# Option 1: Use shell=False with proper argument list
res = subprocess.run(
    ["pgrep", "-l", shlex.quote(name)],
    capture_output=True,
)

# Option 2: Whitelist allowed process names
ALLOWED_PROCESSES = ['python', 'flask', 'gunicorn']
if name not in ALLOWED_PROCESSES:
    return jsonify({"error": "Invalid process name"})
```

---

## 5. Insecure Deserialization

### Status: ⚠️ CRITICAL - REQUIRES MANUAL FIX

### Finding 5.1: Pickle Deserialization
**File:** `flask_webgoat/actions.py` (Lines 57-62)
**Severity:** CRITICAL

```python
data = base64.urlsafe_b64decode(pickled)
# vulnerability: Insecure Deserialization
deserialized = pickle.loads(data)
```

**Attack Vector:** Malicious pickle payload can execute arbitrary code.

**Impact:** Remote code execution through crafted serialized objects.

**Secure Implementation:**
```python
import json

# Use JSON instead of pickle for untrusted data
try:
    data = base64.urlsafe_b64decode(pickled)
    deserialized = json.loads(data.decode('utf-8'))
except (json.JSONDecodeError, ValueError):
    return jsonify({"error": "Invalid data format"})
```

---

## 6. Directory Traversal

### Status: ⚠️ HIGH - REQUIRES MANUAL FIX

### Finding 6.1: Path Traversal in File Writing
**File:** `flask_webgoat/actions.py` (Lines 31-36)
**Severity:** HIGH

```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    # vulnerability: Directory Traversal
    open_file.write(text_param)
```

**Attack Vector:** `filename=../../../etc/cron.d/backdoor`

**Impact:** Arbitrary file write anywhere on the filesystem.

**Secure Implementation:**
```python
from werkzeug.utils import secure_filename

filename = secure_filename(filename_param) + ".txt"
path = Path(user_dir) / filename

# Verify the resolved path is within user_dir
if not path.resolve().is_relative_to(Path(user_dir).resolve()):
    return jsonify({"error": "Invalid filename"})
```

---

## 7. Open Redirect

### Status: ⚠️ MEDIUM - REQUIRES MANUAL FIX

### Finding 7.1: Unvalidated Redirect
**File:** `flask_webgoat/auth.py` (Lines 44-46)
**Severity:** MEDIUM

```python
if result is None:
    # vulnerability: Open Redirect
    return redirect(url)
```

**Attack Vector:** `url=https://evil.com/phishing`

**Impact:** Phishing attacks, credential theft through fake login pages.

**Secure Implementation:**
```python
from urllib.parse import urlparse

def is_safe_url(url):
    """Check if URL is safe for redirect (same host or relative)."""
    if not url:
        return False
    parsed = urlparse(url)
    return not parsed.netloc or parsed.netloc == request.host

if result is None:
    if is_safe_url(url):
        return redirect(url)
    return redirect('/')
```

---

## 8. Broken Access Control

### Status: ⚠️ MEDIUM - REQUIRES MANUAL FIX

### Finding 8.1: Overly Permissive CORS
**File:** `run.py` (Lines 7-8)
**Severity:** MEDIUM

```python
# vulnerability: Broken Access Control
response.headers['Access-Control-Allow-Origin'] = '*'
```

**Impact:** Any website can make requests to this API, enabling CSRF-like attacks and data theft.

**Secure Implementation:**
```python
ALLOWED_ORIGINS = ['https://trusted-domain.com']

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

---

## 9. Security Misconfiguration

### Status: ⚠️ MEDIUM - REQUIRES MANUAL FIX

### Finding 9.1: Weak Content Security Policy
**File:** `run.py` (Lines 9-10)
**Severity:** MEDIUM

```python
# vulnerability: Security Misconfiguration
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

**Impact:** `'unsafe-inline'` allows inline JavaScript execution, enabling XSS attacks.

**Secure Implementation:**
```python
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
```

### Finding 9.2: Missing Security Headers
**Severity:** LOW

Missing recommended security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## 10. Authentication & Authorization Issues

### Status: ⚠️ HIGH - REQUIRES MANUAL FIX

### Finding 10.1: Credentials in URL (GET Request)
**File:** `flask_webgoat/auth.py` (Lines 30-34)
**Severity:** HIGH

```python
@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
```

**Impact:** Credentials exposed in browser history, server logs, referrer headers.

**Recommendation:** Use POST method for authentication endpoints.

### Finding 10.2: Weak Password Policy
**File:** `flask_webgoat/users.py` (Lines 31-34)
**Severity:** MEDIUM

```python
if len(password) < 3:
    return (
        jsonify({"error": "the password needs to be at least 3 characters long"}),
        402,
    )
```

**Recommendation:** Enforce minimum 12 characters, require complexity (uppercase, lowercase, numbers, symbols).

### Finding 10.3: No Session Timeout
**Severity:** LOW

Sessions don't expire, allowing persistent access after authentication.

### Finding 10.4: No Rate Limiting
**Severity:** MEDIUM

No protection against brute-force attacks on login endpoints.

---

## 11. XSS Vulnerabilities

### Status: ⚠️ LOW - POTENTIAL RISK

### Finding 11.1: Template Auto-Escaping
**Files:** `flask_webgoat/templates/*.html`
**Severity:** LOW (Jinja2 auto-escapes by default)

The templates use `{{ variable }}` syntax which is auto-escaped in Jinja2. However, verify no `| safe` filters are used on user input.

**search.html:**
```html
Found {{ num_results }} results for query {{ query }}.
```

While Jinja2 escapes by default, the `'unsafe-inline'` CSP policy could still allow XSS through other vectors.

---

## 12. Remediation Summary

### Fixes Applied in This Audit

| Issue | Status | Action Taken |
|-------|--------|--------------|
| Outdated Dependencies | ✅ Fixed | Updated requirements.txt to latest secure versions |

### Critical Issues Requiring Manual Remediation

| Priority | Issue | File | Line(s) |
|----------|-------|------|---------|
| P0 - Critical | SQL Injection (Login) | auth.py | 17-21 |
| P0 - Critical | SQL Injection (User Creation) | users.py | 37-41 |
| P0 - Critical | Remote Code Execution | actions.py | 43-49 |
| P0 - Critical | Insecure Deserialization | actions.py | 57-62 |
| P0 - Critical | Hardcoded Secret Key | __init__.py | 22 |
| P0 - Critical | Hardcoded Admin Credentials | __init__.py | 33-34 |
| P0 - Critical | Plaintext Password Storage | __init__.py | 33-34 |
| P1 - High | Directory Traversal | actions.py | 31-36 |
| P1 - High | Credentials in URL | auth.py | 30-34 |
| P1 - High | Sensitive Data in Logs | __init__.py | 13 |
| P2 - Medium | Open Redirect | auth.py | 44-46 |
| P2 - Medium | Overly Permissive CORS | run.py | 7-8 |
| P2 - Medium | Weak CSP | run.py | 9-10 |
| P2 - Medium | Weak Password Policy | users.py | 31-34 |
| P2 - Medium | No Rate Limiting | - | - |
| P3 - Low | Missing Security Headers | run.py | - |
| P3 - Low | No Session Timeout | - | - |

---

## Recommendations

### Immediate Actions (P0)
1. **Never deploy this application to production** - it is intentionally vulnerable
2. If adapting code from this project, address all SQL injection points
3. Implement parameterized queries throughout
4. Remove all command execution with user input
5. Replace pickle deserialization with JSON
6. Use environment variables for secrets
7. Hash all passwords with bcrypt/argon2

### Short-term (P1-P2)
1. Implement input validation and sanitization
2. Add rate limiting to authentication endpoints
3. Configure proper CORS policies
4. Strengthen CSP headers
5. Add additional security headers

### Long-term (P3)
1. Implement security testing in CI/CD pipeline
2. Regular dependency audits (e.g., `pip-audit`, `safety`)
3. Security training for development team
4. Consider using security linters (bandit, semgrep)

---

## Tools Used

- Manual code review
- Snyk vulnerability database
- CVE databases (OpenCVE, NVD)

---

*Report generated by Factory AI Security Audit - 2026-04-20*
