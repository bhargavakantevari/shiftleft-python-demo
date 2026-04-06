# Security Audit Report

**Project:** flask-webgoat (shiftleft-python-demo)  
**Date:** 2026-04-06  
**Auditor:** Automated Security Audit  

---

## Executive Summary

This security audit identified **critical vulnerabilities** in both dependencies and application code. The flask-webgoat project is intentionally designed as a vulnerable application for security testing purposes. This report documents all findings and provides remediation guidance.

---

## 1. Dependency Vulnerabilities

### Vulnerable Dependencies Found

| Package | Original Version | Vulnerabilities | Recommended Version |
|---------|------------------|-----------------|---------------------|
| Flask | 0.12.5 | CVE-2023-30861 (Cookie confusion), Multiple security issues | >=3.0.3 |
| Werkzeug | 0.16.1 | CVE-2024-34069 (CSRF), CVE-2023-46136 (DoS), CVE-2026-21860 (Path Traversal) | >=3.0.3 |
| Jinja2 | 2.8 | CVE-2024-22195 (XSS), CVE-2020-28493 (ReDoS), sandbox escape issues | >=3.1.4 |
| itsdangerous | 1.1.0 | Outdated cryptographic practices | >=2.2.0 |
| MarkupSafe | 1.1.1 | Compatibility issues with newer Jinja2 | >=2.1.5 |
| click | 7.1.2 | Outdated, compatibility issues | >=8.1.7 |

### Fixes Applied

✅ **Updated `requirements.txt`** with secure versions:
```
click>=8.1.7
Flask>=3.0.3
itsdangerous>=2.2.0
Jinja2>=3.1.4
MarkupSafe>=2.1.5
Werkzeug>=3.0.3
```

---

## 2. Hardcoded Secrets & API Keys

### Findings

| Location | Issue | Severity | Line |
|----------|-------|----------|------|
| `flask_webgoat/__init__.py` | Hardcoded `secret_key` | **CRITICAL** | 21 |
| `flask_webgoat/__init__.py` | Hardcoded admin password | **CRITICAL** | 32 |

### Details

#### Secret Key Exposure
**File:** `flask_webgoat/__init__.py:21`
```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```
**Risk:** Hardcoded secret keys allow attackers to forge session cookies, bypass authentication, and perform session hijacking.

**Recommendation:**
```python
import os
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
```

#### Default Admin Credentials
**File:** `flask_webgoat/__init__.py:32`
```python
INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)
```
**Risk:** Default credentials are publicly known and provide immediate administrative access.

**Recommendation:**
- Use environment variables for initial admin setup
- Implement password hashing (bcrypt/argon2)
- Force password change on first login

---

## 3. SQL Injection Vulnerabilities

### Findings

| Location | Function | Severity |
|----------|----------|----------|
| `flask_webgoat/auth.py:17-20` | `login()` | **CRITICAL** |
| `flask_webgoat/users.py:37-39` | `create_user()` | **CRITICAL** |

### Details

#### Login SQL Injection
**File:** `flask_webgoat/auth.py:17-20`
```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```
**Attack Vector:** `' OR '1'='1' --` in username field bypasses authentication.

**Recommendation:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

#### Create User SQL Injection
**File:** `flask_webgoat/users.py:37-39`
```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```
**Recommendation:** Use parameterized queries with `?` placeholders.

---

## 4. Remote Code Execution (RCE)

### Findings

| Location | Function | Severity |
|----------|----------|----------|
| `flask_webgoat/actions.py:43-48` | `grep_processes()` | **CRITICAL** |

### Details

**File:** `flask_webgoat/actions.py:43-48`
```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```
**Attack Vector:** Input like `; rm -rf /` or `$(cat /etc/passwd)` executes arbitrary commands.

**Recommendation:**
```python
import shlex
# Validate input
if not name.isalnum():
    return jsonify({"error": "Invalid process name"})
# Use subprocess without shell=True
res = subprocess.run(["pgrep", "-l", name], capture_output=True)
```

---

## 5. Insecure Deserialization

### Findings

| Location | Function | Severity |
|----------|----------|----------|
| `flask_webgoat/actions.py:60-63` | `deserialized_descr()` | **CRITICAL** |

### Details

**File:** `flask_webgoat/actions.py:60-63`
```python
pickled = request.form.get('pickled')
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```
**Attack Vector:** Malicious pickle payloads can execute arbitrary code during deserialization.

**Recommendation:**
- Never deserialize untrusted data with pickle
- Use JSON or other safe serialization formats
- If pickle is required, use `hmac` to verify data integrity

---

## 6. Directory Traversal

### Findings

| Location | Function | Severity |
|----------|----------|----------|
| `flask_webgoat/actions.py:35` | `log_entry()` | **HIGH** |

### Details

**File:** `flask_webgoat/actions.py:28-36`
```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```
**Attack Vector:** `filename=../../../etc/cron.d/malicious` allows writing files outside intended directory.

**Recommendation:**
```python
from pathlib import Path
import os

# Sanitize filename
safe_filename = os.path.basename(filename_param)
if '..' in filename_param or filename_param.startswith('/'):
    return jsonify({"error": "Invalid filename"})
    
# Verify path is within allowed directory
full_path = Path(user_dir).resolve() / (safe_filename + ".txt")
if not str(full_path).startswith(str(Path(user_dir).resolve())):
    return jsonify({"error": "Path traversal detected"})
```

---

## 7. Open Redirect

### Findings

| Location | Function | Severity |
|----------|----------|----------|
| `flask_webgoat/auth.py:45` | `login_and_redirect()` | **MEDIUM** |

### Details

**File:** `flask_webgoat/auth.py:45`
```python
return redirect(url)
```
**Attack Vector:** Attacker-controlled URL parameter redirects users to malicious sites (phishing).

**Recommendation:**
```python
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    return parsed.netloc == '' or parsed.netloc == request.host

if not is_safe_url(url):
    return jsonify({"error": "Invalid redirect URL"}), 400
return redirect(url)
```

---

## 8. Sensitive Data Exposure

### Findings

| Location | Issue | Severity |
|----------|-------|----------|
| `flask_webgoat/__init__.py:12` | SQL query logging | **MEDIUM** |
| `flask_webgoat/__init__.py:32` | Plaintext password storage | **HIGH** |

### Details

#### SQL Query Logging
**File:** `flask_webgoat/__init__.py:12`
```python
conn.set_trace_callback(print)
```
**Risk:** All SQL queries including sensitive data are logged to stdout.

**Recommendation:** Remove or disable in production; use proper logging with redaction.

#### Plaintext Password Storage
Passwords are stored in plaintext in the database.

**Recommendation:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# When storing
hashed = generate_password_hash(password)

# When verifying  
if check_password_hash(stored_hash, provided_password):
    # Login successful
```

---

## 9. Security Misconfiguration

### Findings

| Location | Issue | Severity |
|----------|-------|----------|
| `run.py:7` | Overly permissive CORS | **HIGH** |
| `run.py:9` | Weak CSP allows inline scripts | **MEDIUM** |

### Details

#### CORS Misconfiguration
**File:** `run.py:7`
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```
**Risk:** Any domain can make authenticated requests to this API.

**Recommendation:**
```python
response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
```

#### Weak Content Security Policy
**File:** `run.py:9`
```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```
**Risk:** `unsafe-inline` allows XSS attacks via inline scripts.

**Recommendation:**
```python
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"
```

---

## 10. Cross-Site Scripting (XSS)

### Findings

| Location | Issue | Severity |
|----------|-------|----------|
| `flask_webgoat/templates/search.html` | Reflected XSS potential | **MEDIUM** |
| `flask_webgoat/templates/error.html` | Error message injection | **LOW** |

### Details

While Jinja2 auto-escapes by default, the weak CSP (`unsafe-inline`) combined with user input being displayed could lead to XSS in certain scenarios.

**Templates Analysis:**
- `search.html`: Displays `{{ query }}` and `{{ result }}` - auto-escaped but CSP weakness reduces protection
- `error.html`: Displays `{{ message }}` - auto-escaped

**Recommendation:**
- Strengthen CSP to remove `unsafe-inline`
- Add explicit escaping where needed: `{{ value | e }}`
- Validate/sanitize input on server-side

---

## 11. Authentication & Authorization Issues

### Findings

| Issue | Location | Severity |
|-------|----------|----------|
| No session timeout | Global | **MEDIUM** |
| No rate limiting | All endpoints | **MEDIUM** |
| No CSRF protection | POST endpoints | **HIGH** |
| Credentials in GET params | `auth.py:32` | **MEDIUM** |

### Details

#### Missing CSRF Protection
POST endpoints accept form data without CSRF token verification.

**Recommendation:**
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

#### Credentials in URL
**File:** `flask_webgoat/auth.py:32`
```python
@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
```
**Risk:** Credentials appear in server logs, browser history, and referrer headers.

**Recommendation:** Always use POST for authentication with credentials in request body.

---

## Summary of Fixes Applied

| Category | Action | Status |
|----------|--------|--------|
| Dependencies | Updated requirements.txt with secure versions | ✅ Fixed |
| SQL Injection | Documented, requires code changes | ⚠️ Documented |
| RCE | Documented, requires code changes | ⚠️ Documented |
| Insecure Deserialization | Documented, requires code changes | ⚠️ Documented |
| Directory Traversal | Documented, requires code changes | ⚠️ Documented |
| Hardcoded Secrets | Documented, requires code changes | ⚠️ Documented |
| Open Redirect | Documented, requires code changes | ⚠️ Documented |
| XSS/CSP | Documented, requires code changes | ⚠️ Documented |
| CORS | Documented, requires code changes | ⚠️ Documented |

---

## Risk Rating Summary

| Severity | Count | Issues |
|----------|-------|--------|
| **CRITICAL** | 6 | SQL Injection (2), RCE, Insecure Deserialization, Hardcoded Secret Key, Hardcoded Credentials |
| **HIGH** | 4 | Directory Traversal, Plaintext Passwords, CORS Misconfiguration, Missing CSRF |
| **MEDIUM** | 5 | Open Redirect, SQL Logging, Weak CSP, No Rate Limiting, Credentials in URL |
| **LOW** | 1 | Error Message Injection |

---

## Recommendations Priority

### Immediate (Critical)
1. Update all dependencies to patched versions ✅
2. Remove hardcoded secret key - use environment variables
3. Fix SQL injection vulnerabilities with parameterized queries
4. Remove shell=True from subprocess calls
5. Replace pickle with safe serialization

### Short-term (High)
1. Implement password hashing
2. Add path validation for file operations
3. Restrict CORS to specific domains
4. Add CSRF protection

### Medium-term (Medium/Low)
1. Implement rate limiting
2. Add session timeout
3. Strengthen Content Security Policy
4. Add input validation across all endpoints
5. Implement proper logging with sensitive data redaction

---

*Note: This is an intentionally vulnerable application (WebGoat). The vulnerabilities documented here are by design for educational purposes. Do not deploy this application in production.*
