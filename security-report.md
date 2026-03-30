# Security Audit Report

**Project:** flask-webgoat  
**Date:** 2026-03-30  
**Auditor:** Automated Security Audit

---

## Executive Summary

This security audit identified **CRITICAL** vulnerabilities throughout the application. The flask-webgoat project is intentionally designed as a vulnerable application for educational purposes. However, this report documents all findings and provides remediation guidance.

### Risk Summary
| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 4 |
| Medium | 3 |
| Low | 2 |

---

## 1. Dependency Vulnerabilities

### 1.1 Outdated and Vulnerable Dependencies (CRITICAL)

**Location:** `requirements.txt`

**Original vulnerable versions:**
```
Flask==0.12.5
Werkzeug==0.16.1
Jinja2==2.8
itsdangerous==1.1.0
MarkupSafe==1.1.1
click==7.1.2
```

**Known CVEs:**

| Package | Old Version | CVEs | Severity |
|---------|-------------|------|----------|
| Flask | 0.12.5 | CVE-2023-30861 (cookie session confusion), CVE-2019-1010083 (DoS) | High |
| Werkzeug | 0.16.1 | CVE-2024-34069 (debugger RCE), CVE-2023-25577 (DoS), CVE-2023-23934 (cookie parsing) | Critical |
| Jinja2 | 2.8 | CVE-2024-22195 (XSS), CVE-2020-28493 (ReDoS), CVE-2019-10906 (sandbox escape), CVE-2019-8341 (SSTI) | Critical |
| MarkupSafe | 1.1.1 | CVE-2024-23334 (ReDoS) | Medium |

**Fix Applied:**
```
click>=8.1.0
Flask>=3.0.0
itsdangerous>=2.1.0
Jinja2>=3.1.3
MarkupSafe>=2.1.5
Werkzeug>=3.0.1
```

**Status:** ✅ FIXED in requirements.txt

---

## 2. Hardcoded Secrets and Credentials

### 2.1 Hardcoded Flask Secret Key (CRITICAL)

**Location:** `flask_webgoat/__init__.py:21`

**Vulnerable Code:**
```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```

**Risk:** Attackers can forge session cookies if they know the secret key, leading to session hijacking and authentication bypass.

**Recommended Fix:**
```python
import os
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)
```

**Status:** ⚠️ REQUIRES MANUAL FIX

### 2.2 Hardcoded Admin Credentials (CRITICAL)

**Location:** `flask_webgoat/__init__.py:29-30`

**Vulnerable Code:**
```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

**Risk:** Admin credentials are exposed in source code. Passwords stored in plaintext.

**Recommended Fix:**
- Use environment variables for initial admin setup
- Hash passwords using bcrypt or argon2
- Never store plaintext passwords

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 3. SQL Injection Vulnerabilities

### 3.1 SQL Injection in Login (CRITICAL)

**Location:** `flask_webgoat/auth.py:17-21`

**Vulnerable Code:**
```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```

**Attack Vector:** `username=' OR '1'='1' --`

**Recommended Fix:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

**Status:** ⚠️ REQUIRES MANUAL FIX

### 3.2 SQL Injection in User Creation (CRITICAL)

**Location:** `flask_webgoat/users.py:37-40`

**Vulnerable Code:**
```python
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

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 4. Remote Code Execution (RCE)

### 4.1 Command Injection (CRITICAL)

**Location:** `flask_webgoat/actions.py:43-48`

**Vulnerable Code:**
```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

**Attack Vector:** `name=; cat /etc/passwd`

**Recommended Fix:**
```python
import shlex

# Validate input
if not name or not name.isalnum():
    return jsonify({"error": "Invalid process name"})

# Use list of arguments without shell=True
res = subprocess.run(
    ["ps", "aux"],
    capture_output=True,
    text=True
)
# Filter in Python instead of using shell pipes
```

**Status:** ⚠️ REQUIRES MANUAL FIX

### 4.2 Insecure Deserialization (CRITICAL)

**Location:** `flask_webgoat/actions.py:60-62`

**Vulnerable Code:**
```python
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```

**Risk:** Arbitrary code execution via crafted pickle payloads.

**Recommended Fix:**
```python
import json
# Use JSON instead of pickle for untrusted data
try:
    data = base64.urlsafe_b64decode(pickled)
    deserialized = json.loads(data)
except (json.JSONDecodeError, ValueError):
    return jsonify({"error": "Invalid data format"})
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 5. Path Traversal / Directory Traversal

### 5.1 Directory Traversal in File Write (HIGH)

**Location:** `flask_webgoat/actions.py:35`

**Vulnerable Code:**
```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

**Attack Vector:** `filename=../../../etc/passwd`

**Recommended Fix:**
```python
import os.path

# Sanitize filename
safe_filename = os.path.basename(filename_param)
if not safe_filename or safe_filename.startswith('.'):
    return jsonify({"error": "Invalid filename"})

path = Path(user_dir) / (safe_filename + ".txt")

# Verify the resolved path is within the expected directory
if not str(path.resolve()).startswith(str(Path(user_dir).resolve())):
    return jsonify({"error": "Invalid path"})
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 6. Open Redirect Vulnerability

### 6.1 Unvalidated Redirect (HIGH)

**Location:** `flask_webgoat/auth.py:45`

**Vulnerable Code:**
```python
if result is None:
    return redirect(url)
```

**Attack Vector:** `url=https://malicious-site.com`

**Recommended Fix:**
```python
from urllib.parse import urlparse

def is_safe_url(url):
    """Check if URL is safe (relative or same host)."""
    if not url:
        return False
    parsed = urlparse(url)
    return not parsed.netloc or parsed.netloc == request.host

if result is None:
    if not is_safe_url(url):
        return jsonify({"error": "Invalid redirect URL"}), 400
    return redirect(url)
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 7. Sensitive Data Exposure

### 7.1 Database Query Logging (MEDIUM)

**Location:** `flask_webgoat/__init__.py:12`

**Vulnerable Code:**
```python
conn.set_trace_callback(print)
```

**Risk:** All SQL queries including passwords are printed to stdout/logs.

**Recommended Fix:**
```python
# Remove trace callback in production
if app.debug:
    conn.set_trace_callback(print)
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 8. Security Misconfiguration

### 8.1 Overly Permissive CORS (HIGH)

**Location:** `run.py:7`

**Vulnerable Code:**
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

**Risk:** Allows any website to make requests to this API.

**Recommended Fix:**
```python
ALLOWED_ORIGINS = ['https://trusted-domain.com']
origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
```

**Status:** ⚠️ REQUIRES MANUAL FIX

### 8.2 Unsafe Content Security Policy (MEDIUM)

**Location:** `run.py:9`

**Vulnerable Code:**
```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

**Risk:** `'unsafe-inline'` allows inline scripts, enabling XSS attacks.

**Recommended Fix:**
```python
response.headers['Content-Security-Policy'] = "script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'"
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## 9. Cross-Site Scripting (XSS)

### 9.1 Reflected XSS in Templates (MEDIUM)

**Location:** `flask_webgoat/templates/search.html`

**Analysis:** Jinja2 auto-escapes variables by default using `{{ }}` syntax, but the application uses vulnerable Jinja2 2.8 which has known XSS vulnerabilities.

**Current Code:**
```html
Found {{ num_results }} results for query {{ query }}.
```

**Risk:** With Jinja2 2.8, certain edge cases may bypass auto-escaping.

**Recommended Fix:**
- Update to Jinja2 >= 3.1.3 (done in requirements.txt)
- Explicitly escape user input: `{{ query | e }}`

**Status:** ✅ PARTIALLY FIXED (dependency updated)

---

## 10. Authentication & Authorization Issues

### 10.1 Plaintext Password Storage (HIGH)

**Location:** `flask_webgoat/__init__.py`, `flask_webgoat/users.py`

**Issue:** Passwords are stored in plaintext in the SQLite database.

**Recommended Fix:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# When creating user
hashed_password = generate_password_hash(password)

# When verifying
if check_password_hash(stored_hash, provided_password):
    # Login success
```

**Status:** ⚠️ REQUIRES MANUAL FIX

### 10.2 Weak Password Policy (LOW)

**Location:** `flask_webgoat/users.py:31-35`

**Issue:** Only requires 3 character minimum password length.

**Recommended Fix:**
- Minimum 12 characters
- Require uppercase, lowercase, numbers, special characters
- Check against common password lists

**Status:** ⚠️ REQUIRES MANUAL FIX

### 10.3 Missing Session Timeout (LOW)

**Issue:** Sessions don't expire, allowing indefinite access.

**Recommended Fix:**
```python
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=1)
```

**Status:** ⚠️ REQUIRES MANUAL FIX

---

## Summary of Changes Made

### Files Modified:
1. **requirements.txt** - Updated all dependencies to secure versions

### Pending Manual Fixes:
1. Replace hardcoded secrets with environment variables
2. Hash passwords using secure algorithms
3. Use parameterized queries to prevent SQL injection
4. Sanitize user input to prevent command injection
5. Remove pickle deserialization or use safe alternatives
6. Implement path traversal protection
7. Validate redirect URLs
8. Remove debug logging of sensitive data
9. Implement proper CORS policy
10. Strengthen Content Security Policy
11. Implement proper password hashing
12. Add password complexity requirements
13. Implement session timeouts

---

## Recommendations

### Immediate Actions (Critical):
1. Never deploy this application to production
2. Update dependencies (DONE)
3. Replace all hardcoded secrets
4. Fix all SQL injection vulnerabilities
5. Remove command injection vulnerability
6. Remove insecure deserialization

### Short-term Actions (High):
1. Implement password hashing
2. Fix path traversal vulnerability
3. Implement proper CORS
4. Fix open redirect

### Long-term Actions (Medium/Low):
1. Implement comprehensive input validation
2. Add rate limiting
3. Implement proper logging (without sensitive data)
4. Add security headers (X-Frame-Options, X-Content-Type-Options, etc.)
5. Implement CSRF protection
6. Add session management improvements

---

## Note

**This application (flask-webgoat) is intentionally vulnerable and designed for security education purposes. It should NEVER be deployed to production or exposed to untrusted networks.**

---

*Report generated by automated security audit*
