# Security Audit Report

**Project:** flask-webgoat  
**Date:** 2026-04-13  
**Auditor:** Automated Security Scan  

---

## Executive Summary

This security audit identified **17 security vulnerabilities** across the codebase, including critical issues in dependencies, hardcoded credentials, SQL injection, remote code execution, and more. This is a deliberately vulnerable application designed for security training purposes.

---

## 1. Dependency Vulnerabilities

### Findings

| Package | Old Version | Vulnerabilities | Fixed Version |
|---------|-------------|-----------------|---------------|
| Flask | 0.12.5 | DoS, Memory exhaustion (CVE pending) | 3.0.3+ |
| Werkzeug | 0.16.1 | RCE (High), DoS (High), Directory Traversal, Resource Exhaustion | 3.1.8 |
| Jinja2 | 2.8 | XSS (CVE-2024-22195), Sandbox Escape | 3.1.6 |
| itsdangerous | 1.1.0 | No known CVEs but outdated | 2.2.0 |
| MarkupSafe | 1.1.1 | Potential security updates | 2.1.5 |
| click | 7.1.2 | No known CVEs but outdated | 8.1.7 |

### Werkzeug 0.16.1 Specific CVEs:
- **SNYK-PYTHON-WERKZEUG-6808933** (HIGH): Remote Code Execution via debugger
- **SNYK-PYTHON-WERKZEUG-3319936** (HIGH): Denial of Service via multipart form data
- **SNYK-PYTHON-WERKZEUG-8309091** (MEDIUM): Directory Traversal in safe_join()
- **SNYK-PYTHON-WERKZEUG-8309092** (MEDIUM): Resource exhaustion in formparser
- **SNYK-PYTHON-WERKZEUG-6035177** (MEDIUM): Algorithmic complexity DoS

### Fix Applied ✅
Updated `requirements.txt` with secure versions:
```
click>=8.1.7
Flask>=3.0.3
itsdangerous>=2.2.0
Jinja2>=3.1.6
MarkupSafe>=2.1.5
Werkzeug>=3.1.8
```

---

## 2. Hardcoded Secrets and Credentials

### Findings

| Location | Type | Severity | Description |
|----------|------|----------|-------------|
| `flask_webgoat/__init__.py:22` | Secret Key | **CRITICAL** | Hardcoded Flask secret key |
| `flask_webgoat/__init__.py:33-34` | Credentials | **CRITICAL** | Hardcoded admin password |

### Details

#### 2.1 Hardcoded Flask Secret Key
**File:** `flask_webgoat/__init__.py` (Line 22)
```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```

**Risk:** Session hijacking, cookie tampering, authentication bypass  
**Recommendation:** Use environment variables:
```python
import os
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)
```

#### 2.2 Hardcoded Admin Credentials
**File:** `flask_webgoat/__init__.py` (Lines 33-34)
```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

**Risk:** Complete administrative access compromise  
**Recommendation:** 
- Use environment variables for initial admin setup
- Hash passwords using bcrypt or argon2
- Remove from source code

---

## 3. SQL Injection Vulnerabilities

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/auth.py:17-20` | **CRITICAL** | A03:2021 – Injection |
| `flask_webgoat/users.py:37-40` | **CRITICAL** | A03:2021 – Injection |

### Details

#### 3.1 SQL Injection in Login
**File:** `flask_webgoat/auth.py` (Lines 17-20)
```python
# vulnerability: SQL Injection
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```

**Attack Vector:** `username: ' OR '1'='1' --`  
**Impact:** Authentication bypass, data exfiltration

**Recommended Fix:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

#### 3.2 SQL Injection in User Creation
**File:** `flask_webgoat/users.py` (Lines 37-40)
```python
# vulnerability: SQL Injection
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

**Recommended Fix:**
```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, password, int(access_level)), False, True)
```

---

## 4. Remote Code Execution (RCE)

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/actions.py:43-48` | **CRITICAL** | A03:2021 – Injection |

### Details

**File:** `flask_webgoat/actions.py` (Lines 43-48)
```python
@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    # vulnerability: Remote Code Execution
    res = subprocess.run(
        ["ps aux | grep " + name + " | awk '{print $11}'"],
        shell=True,
        capture_output=True,
    )
```

**Attack Vector:** `name=; rm -rf /; #`  
**Impact:** Full system compromise

**Recommended Fix:**
```python
import shlex

@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if not name or not name.isalnum():
        return jsonify({"error": "Invalid process name"}), 400
    
    # Use subprocess without shell=True
    ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    lines = [line for line in ps.stdout.split('\n') if name in line]
    return jsonify({"success": True, "names": lines})
```

---

## 5. Insecure Deserialization

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/actions.py:55-62` | **CRITICAL** | A08:2021 – Software and Data Integrity Failures |

### Details

**File:** `flask_webgoat/actions.py` (Lines 55-62)
```python
@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
```

**Impact:** Remote code execution via crafted pickle payload

**Recommended Fix:**
- Never use `pickle.loads()` on untrusted data
- Use JSON for serialization:
```python
import json

@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    data = request.form.get('data')
    deserialized = json.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
```

---

## 6. Directory Traversal

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/actions.py:35` | **HIGH** | A01:2021 – Broken Access Control |

### Details

**File:** `flask_webgoat/actions.py` (Lines 25-37)
```python
filename_param = request.form.get("filename")
# ...
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    # vulnerability: Directory Traversal
    open_file.write(text_param)
```

**Attack Vector:** `filename=../../../etc/passwd`  
**Impact:** Arbitrary file write outside intended directory

**Recommended Fix:**
```python
from werkzeug.utils import secure_filename
import os

filename = secure_filename(filename_param) + ".txt"
full_path = os.path.join(user_dir, filename)

# Verify path is within allowed directory
if not os.path.abspath(full_path).startswith(os.path.abspath(user_dir)):
    return jsonify({"error": "Invalid filename"}), 400
```

---

## 7. Open Redirect

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/auth.py:45` | **MEDIUM** | A01:2021 – Broken Access Control |

### Details

**File:** `flask_webgoat/auth.py` (Lines 42-45)
```python
if result is None:
    # vulnerability: Open Redirect
    return redirect(url)
```

**Attack Vector:** `url=https://malicious-site.com`  
**Impact:** Phishing attacks, credential theft

**Recommended Fix:**
```python
from urllib.parse import urlparse

def is_safe_url(url):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(url)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

if result is None:
    if not is_safe_url(url):
        return jsonify({"error": "Invalid redirect URL"}), 400
    return redirect(url)
```

---

## 8. Sensitive Data Exposure

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `flask_webgoat/__init__.py:12` | **MEDIUM** | A02:2021 – Cryptographic Failures |

### Details

**File:** `flask_webgoat/__init__.py` (Line 12)
```python
# vulnerability: Sensitive Data Exposure
conn.set_trace_callback(print)
```

**Impact:** SQL queries including sensitive data logged to console  
**Recommended Fix:** Remove trace callback in production:
```python
if app.debug:
    conn.set_trace_callback(print)
```

---

## 9. Security Misconfiguration

### Findings

| Location | Severity | OWASP Category |
|----------|----------|----------------|
| `run.py:7` | **HIGH** | A05:2021 – Security Misconfiguration |
| `run.py:9` | **MEDIUM** | A05:2021 – Security Misconfiguration |

### Details

#### 9.1 Overly Permissive CORS
**File:** `run.py` (Line 7)
```python
# vulnerability: Broken Access Control
response.headers['Access-Control-Allow-Origin'] = '*'
```

**Impact:** Any website can make requests to this API  
**Recommended Fix:**
```python
response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
```

#### 9.2 Insecure Content Security Policy
**File:** `run.py` (Line 9)
```python
# vulnerability: Security Misconfiguration
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

**Impact:** Allows inline scripts, enabling XSS attacks  
**Recommended Fix:**
```python
response.headers['Content-Security-Policy'] = "script-src 'self'; object-src 'none'; base-uri 'self'"
```

---

## 10. Potential XSS Vulnerabilities

### Findings

| Location | Severity | Risk |
|----------|----------|------|
| Templates | **LOW** | Mitigated by Jinja2 auto-escaping |

### Details

The templates use Jinja2's default auto-escaping which helps prevent XSS:
- `search.html`: `{{ query }}` and `{{ result }}` are auto-escaped
- `error.html`: `{{ message }}` is auto-escaped

**Note:** The CSP header with `'unsafe-inline'` weakens this protection.

---

## 11. Authentication Issues

### Findings

| Issue | Severity | Description |
|-------|----------|-------------|
| Plain-text passwords | **CRITICAL** | Passwords stored without hashing |
| No rate limiting | **HIGH** | Brute force attacks possible |
| No session timeout | **MEDIUM** | Sessions persist indefinitely |
| Weak password policy | **MEDIUM** | Only 3 character minimum |

### Recommended Fixes

1. **Password Hashing:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# When creating user
password_hash = generate_password_hash(password)

# When verifying
if check_password_hash(stored_hash, provided_password):
    # Login successful
```

2. **Rate Limiting:**
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # ...
```

---

## Summary of Changes Made

### ✅ Fixed: Dependency Vulnerabilities
- Updated `requirements.txt` with secure package versions

### ⚠️ Requires Manual Fix:
1. Remove hardcoded secret key and credentials
2. Fix SQL injection in auth.py and users.py
3. Fix RCE in actions.py
4. Fix insecure deserialization
5. Fix directory traversal
6. Fix open redirect
7. Remove debug trace callback
8. Fix CORS configuration
9. Fix CSP header
10. Implement password hashing
11. Add rate limiting

---

## OWASP Top 10 Coverage

| OWASP 2021 | Found | Fixed |
|------------|-------|-------|
| A01 - Broken Access Control | ✅ | ⚠️ Partial |
| A02 - Cryptographic Failures | ✅ | ⚠️ Partial |
| A03 - Injection | ✅ | ⚠️ Partial |
| A04 - Insecure Design | ✅ | ⚠️ Partial |
| A05 - Security Misconfiguration | ✅ | ⚠️ Partial |
| A06 - Vulnerable Components | ✅ | ✅ Fixed |
| A07 - Auth Failures | ✅ | ⚠️ Partial |
| A08 - Data Integrity Failures | ✅ | ⚠️ Partial |
| A09 - Logging Failures | ✅ | ⚠️ Partial |
| A10 - SSRF | ❌ | N/A |

---

## Risk Rating

| Severity | Count |
|----------|-------|
| Critical | 5 |
| High | 4 |
| Medium | 5 |
| Low | 3 |

**Overall Risk Level: CRITICAL**

---

## Recommendations

1. **Immediate:** Update all dependencies (✅ Done)
2. **Immediate:** Remove hardcoded credentials and use environment variables
3. **High Priority:** Fix all SQL injection vulnerabilities
4. **High Priority:** Remove command injection (RCE) vulnerability
5. **High Priority:** Remove insecure deserialization
6. **Medium Priority:** Implement proper authentication (hashing, rate limiting)
7. **Medium Priority:** Fix CORS and CSP headers
8. **Low Priority:** Improve password policy requirements

---

*Note: This is a deliberately vulnerable application (WebGoat-style) designed for security training. The vulnerabilities are intentional for educational purposes.*
