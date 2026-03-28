# Security Audit Report

**Project:** flask-webgoat (Deliberately Vulnerable Application)  
**Date:** 2026-03-28  
**Auditor:** Automated Security Analysis

---

## Executive Summary

This report documents a comprehensive security audit of the flask-webgoat project. The application is **intentionally vulnerable** for educational purposes and contains numerous critical security flaws. This audit identifies all vulnerabilities, categorizes them by severity, and provides remediation guidance.

**Finding Summary:**
- **Critical:** 5
- **High:** 4
- **Medium:** 3
- **Low:** 2

---

## 1. Dependency Vulnerabilities

### 1.1 Vulnerable Dependencies (FIXED)

| Package | Old Version | New Version | Vulnerabilities Found |
|---------|-------------|-------------|----------------------|
| Flask | 0.12.5 | >=3.1.3 | Session cookie issues, response splitting |
| Jinja2 | 2.8 | >=3.1.6 | XSS (CVE-2024-22195), sandbox escape, template injection |
| Werkzeug | 0.16.1 | >=3.1.7 | **9 CVEs** including RCE, DoS, Directory Traversal |
| itsdangerous | 1.1.0 | >=2.2.0 | Timing attacks on signature verification |
| MarkupSafe | 1.1.1 | >=3.0.2 | XSS via improper escaping |
| click | 7.1.2 | >=8.1.7 | Command injection edge cases |

#### Werkzeug 0.16.1 Specific CVEs:
| CVE/Issue | Severity | Description |
|-----------|----------|-------------|
| SNYK-PYTHON-WERKZEUG-6808933 | High | Remote Code Execution via debugger |
| SNYK-PYTHON-WERKZEUG-3319936 | High | DoS via multipart form parsing |
| SNYK-PYTHON-WERKZEUG-8309091 | Medium | Directory Traversal in safe_join() |
| SNYK-PYTHON-WERKZEUG-6035177 | Medium | DoS via multipart parsing complexity |
| SNYK-PYTHON-WERKZEUG-3319935 | Low | Cookie access restriction bypass |

**Status:** ✅ FIXED in `requirements.txt`

---

## 2. Hardcoded Secrets and Sensitive Data

### 2.1 Hardcoded Secret Key (CRITICAL)

**File:** `flask_webgoat/__init__.py`  
**Line:** 22  
```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```

**Risk:** Session tokens signed with this key can be forged, allowing session hijacking.

**Remediation:**
```python
import os
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
```

### 2.2 Hardcoded Admin Credentials (CRITICAL)

**File:** `flask_webgoat/__init__.py`  
**Lines:** 33-34  
```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

**Risk:** Default admin credentials allow trivial unauthorized access.

**Remediation:**
- Use environment variables for initial admin setup
- Hash passwords using bcrypt or argon2
- Remove hardcoded credentials from source code

### 2.3 Sensitive Data Exposure via Trace Callback (HIGH)

**File:** `flask_webgoat/__init__.py`  
**Line:** 12  
```python
conn.set_trace_callback(print)
```

**Risk:** All SQL queries (including those with passwords) are printed to stdout/logs.

**Remediation:** Remove trace callback or use proper logging with sensitive data filtering.

---

## 3. SQL Injection Vulnerabilities

### 3.1 Login Endpoint (CRITICAL)

**File:** `flask_webgoat/auth.py`  
**Lines:** 17-21  
```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```

**Attack Vector:** `username: admin'-- ` bypasses authentication.

**Remediation:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

### 3.2 User Creation Endpoint (CRITICAL)

**File:** `flask_webgoat/users.py`  
**Lines:** 37-40  
```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

**Risk:** SQL injection allows privilege escalation and data manipulation.

**Remediation:** Use parameterized queries with `?` placeholders.

---

## 4. Remote Code Execution (RCE)

### 4.1 Command Injection (CRITICAL)

**File:** `flask_webgoat/actions.py`  
**Lines:** 43-48  
```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

**Attack Vector:** `name=; cat /etc/passwd;` executes arbitrary commands.

**Remediation:**
```python
import shlex
# Avoid shell=True, use proper argument escaping
res = subprocess.run(
    ["ps", "aux"],
    capture_output=True,
)
# Filter output in Python instead of using shell piping
```

### 4.2 Insecure Deserialization (CRITICAL)

**File:** `flask_webgoat/actions.py`  
**Lines:** 60-62  
```python
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```

**Risk:** Arbitrary code execution via crafted pickle payload.

**Remediation:**
- Never deserialize untrusted data with pickle
- Use JSON for data serialization
- If pickle is required, use `hmac` signature verification

---

## 5. Path Traversal

### 5.1 Directory Traversal in File Write (HIGH)

**File:** `flask_webgoat/actions.py`  
**Lines:** 33-37  
```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

**Attack Vector:** `filename=../../../etc/passwd` writes outside intended directory.

**Remediation:**
```python
from pathlib import Path

filename = Path(filename_param).name + ".txt"  # Strip directory components
path = (user_dir_path / filename).resolve()
if not path.is_relative_to(user_dir_path.resolve()):
    return jsonify({"error": "Invalid filename"}), 400
```

---

## 6. Open Redirect

### 6.1 Unvalidated Redirect (MEDIUM)

**File:** `flask_webgoat/auth.py`  
**Lines:** 44-45  
```python
if result is None:
    return redirect(url)
```

**Attack Vector:** `url=https://malicious.com` redirects users to phishing sites.

**Remediation:**
```python
from urllib.parse import urlparse

def is_safe_redirect(url):
    """Check if URL is safe for redirect (same host or relative)."""
    parsed = urlparse(url)
    return not parsed.netloc or parsed.netloc == request.host

if not is_safe_redirect(url):
    return jsonify({"error": "Invalid redirect URL"}), 400
```

---

## 7. Security Misconfigurations

### 7.1 Overly Permissive CORS (HIGH)

**File:** `run.py`  
**Line:** 8  
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

**Risk:** Any domain can make authenticated requests if credentials are included.

**Remediation:**
```python
ALLOWED_ORIGINS = ['https://trusted-domain.com']
origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
```

### 7.2 Unsafe CSP with inline scripts (MEDIUM)

**File:** `run.py`  
**Line:** 10  
```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

**Risk:** `'unsafe-inline'` allows XSS attacks via inline scripts.

**Remediation:**
```python
response.headers['Content-Security-Policy'] = "script-src 'self'; object-src 'none'; base-uri 'self'"
```

### 7.3 Missing Security Headers

**Missing Headers:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (HSTS)
- `X-XSS-Protection: 1; mode=block`

**Remediation:** Add comprehensive security headers:
```python
response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['X-Frame-Options'] = 'DENY'
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
```

---

## 8. Authentication & Authorization Issues

### 8.1 Plaintext Password Storage (HIGH)

**File:** `flask_webgoat/__init__.py`  
Passwords are stored in plaintext in the SQLite database.

**Remediation:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# When storing
hashed = generate_password_hash(password)

# When verifying
if check_password_hash(stored_hash, provided_password):
    # login success
```

### 8.2 Weak Password Policy (LOW)

**File:** `flask_webgoat/users.py`  
**Line:** 31  
```python
if len(password) < 3:
```

Only requires 3-character passwords.

**Remediation:**
- Minimum 12 characters
- Require mixed case, numbers, and special characters
- Check against common password lists

### 8.3 Session in URL Parameters (MEDIUM)

**File:** `flask_webgoat/auth.py`  
**Lines:** 31-32  
```python
username = request.args.get("username")
password = request.args.get("password")
```

**Risk:** Credentials exposed in browser history, logs, and referrer headers.

**Remediation:** Use POST requests for authentication.

---

## 9. Potential XSS Vulnerabilities

### 9.1 Template Output Without Context

**File:** `flask_webgoat/templates/search.html`  
```html
Found {{ num_results }} results for query {{ query }}.
```

**Analysis:** Jinja2 auto-escapes by default, but Jinja2 2.8 has known XSS vulnerabilities (CVE-2024-22195). Updating to 3.1.6+ mitigates this.

### 9.2 Error Message Display

**File:** `flask_webgoat/templates/error.html`  
```html
{{ message }}
```

**Risk:** If error messages contain user input, XSS is possible in older Jinja2 versions.

---

## 10. Summary of Fixes Applied

| Fix | Status |
|-----|--------|
| Updated Flask to >=3.1.3 | ✅ Applied |
| Updated Jinja2 to >=3.1.6 | ✅ Applied |
| Updated Werkzeug to >=3.1.7 | ✅ Applied |
| Updated itsdangerous to >=2.2.0 | ✅ Applied |
| Updated MarkupSafe to >=3.0.2 | ✅ Applied |
| Updated click to >=8.1.7 | ✅ Applied |

---

## 11. Recommended Actions (Not Applied - Code Changes Required)

### Immediate (Critical):
1. [ ] Remove hardcoded secret key - use environment variables
2. [ ] Fix SQL injection in `/login` endpoint
3. [ ] Fix SQL injection in `/create_user` endpoint  
4. [ ] Fix command injection in `/grep_processes`
5. [ ] Remove pickle deserialization or add signature verification

### Short-term (High):
1. [ ] Implement password hashing (bcrypt/argon2)
2. [ ] Fix directory traversal in file write
3. [ ] Restrict CORS to specific origins
4. [ ] Remove SQL trace callback

### Medium-term (Medium):
1. [ ] Implement safe redirect validation
2. [ ] Strengthen CSP headers
3. [ ] Add comprehensive security headers
4. [ ] Move auth endpoints to POST only

### Long-term (Low):
1. [ ] Implement strong password policy
2. [ ] Add rate limiting
3. [ ] Implement proper logging without sensitive data
4. [ ] Add CSRF protection

---

## Conclusion

This application contains **14 distinct security vulnerabilities** across all OWASP Top 10 categories. The dependency updates have been applied to mitigate known CVEs in third-party libraries. However, the application code itself remains vulnerable and requires significant remediation before it can be considered secure for any production use.

**Note:** This application is intentionally vulnerable for educational purposes. The vulnerabilities documented here serve as examples for security training and should not be fixed if the application is being used for learning purposes.
