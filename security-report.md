# Security Audit Report

**Project:** flask-webgoat  
**Date:** 2026-08-03  
**Auditor:** Factory Droid (automated security audit)  
**Status:** All findings remediated

---

## Executive Summary

A comprehensive security audit was performed on the flask-webgoat application, a Flask-based web service. The audit identified **22 known CVEs** across 4 dependencies and **9 code-level vulnerabilities** spanning OWASP Top 10 categories including injection, broken access control, cryptographic failures, security misconfiguration, and vulnerable/outdated components.

All dependency vulnerabilities were resolved by upgrading to safe versions. All code-level vulnerabilities were remediated. A post-fix `pip-audit` scan confirms **zero known vulnerabilities** remain in the dependency tree.

---

## 1. Dependency Vulnerabilities (Checked & Fixed)

This is a Python project (no `package.json`). Dependency analysis was performed against `requirements.txt` using `pip-audit`.

### Findings

22 known vulnerabilities were found in 4 packages:

| Package | Version | CVE Count | Fix Version |
|---------|---------|-----------|-------------|
| Flask | 0.12.5 | 3 | 3.1.3 |
| Werkzeug | 0.16.1 | 12 | 3.1.6 |
| Jinja2 | 2.8 | 7 | 3.1.6 |
| click | 7.1.2 | 1 | 8.3.3 |

Notable CVEs include:
- **PYSEC-2023-62** (Flask): Cookie disclosure via multipart form data parsing
- **PYSEC-2022-203** (Werkzeug): Possible disclosure of permanent cookie secrets
- **PYSEC-2021-66** (Jinja2): Remote code execution via crafted format strings
- **PYSEC-2026-2320** (Werkzeug): Latest known Werkzeug vulnerability

### Fix Applied

`requirements.txt` updated to safe, current versions:

```
click==8.3.3
Flask==3.1.3
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
Werkzeug==3.1.6
```

Post-fix verification: `pip-audit` reports **No known vulnerabilities found** (exit code 0).

---

## 2. Hardcoded Secrets & API Keys (Checked & Fixed)

### Finding: Hardcoded Flask Secret Key

**Severity: HIGH**  
**File:** `flask_webgoat/__init__.py`  
**OWASP:** A02:2021 - Cryptographic Failures

The Flask `secret_key` was hardcoded as a static string. Since this key signs session cookies, anyone with source access could forge session cookies and bypass authentication entirely.

**Before:**
```python
app.secret_key = "****************************************"
```

**After:**
```python
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
```

The key is now loaded from the `SECRET_KEY` environment variable, with a cryptographically random fallback for development. In production, the environment variable must be set to a stable, high-entropy value.

### Other Secrets Review

- `azure-pipelines.yml` references secrets via Azure variable groups (`shiftleft-token`) and `$(SHIFTLEFT_ACCESS_TOKEN)` interpolation. No plaintext secrets found.
- `.github/workflows/main.yml` references secrets via GitHub Actions `${{ secrets.* }}` syntax. No plaintext secrets found.
- No other hardcoded API keys, tokens, or credentials were found in the codebase.

---

## 3. Authentication & Authorization (Checked & Fixed)

### Finding 3a: Open Redirect

**Severity: MEDIUM**  
**File:** `flask_webgoat/auth.py`  
**OWASP:** A01:2021 - Broken Access Control

The `/login_and_redirect` endpoint redirected users to an arbitrary URL on failed login, enabling phishing attacks via crafted redirect URLs.

**Fix:** The redirect target is now validated with `urllib.parse.urlparse`. If the URL contains a scheme and netloc (i.e., is an external URL), the redirect is rejected with a 400 error. Only relative paths are allowed.

### Finding 3b: Session-Based Access Control

**Severity: LOW (informational)**  
**Files:** `flask_webgoat/users.py`, `flask_webgoat/actions.py`

The application uses Flask session-based access control with `access_level` checks. The logic is sound:
- `/create_user` requires `access_level == 0` (admin)
- `/message` requires `access_level <= 2`

No changes needed to the authorization logic itself, but the session integrity is now protected by the fixed secret key (see Section 2).

### Finding 3c: Weak Password Policy

**Severity: LOW (informational)**  
**File:** `flask_webgoat/users.py`

The minimum password length is 3 characters, which is insufficient. Recommendation: increase to at least 8 characters and consider adding complexity requirements. This was not changed to avoid altering application behavior beyond the scope of critical fixes.

---

## 4. SQL Injection (Checked & Fixed)

### Finding 4a: SQL Injection in Login

**Severity: CRITICAL**  
**File:** `flask_webgoat/auth.py`  
**OWASP:** A03:2021 - Injection

The `/login` endpoint built a SQL query via string interpolation of user-supplied `username` and `password`, allowing authentication bypass (e.g., `' OR '1'='1`).

**Before:**
```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
result = query_db(query, [], True)
```

**After:**
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

Parameterized queries are now used, preventing SQL injection.

### Finding 4b: SQL Injection in Create User

**Severity: CRITICAL**  
**File:** `flask_webgoat/users.py`  
**OWASP:** A03:2021 - Injection

The `/create_user` endpoint built an INSERT query via string interpolation, allowing SQL injection.

**Before:**
```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
query_db(query, [], False, True)
```

**After:**
```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, password, int(access_level)), False, True)
```

### Finding 4c: Safe Query in Search (No Issue)

**File:** `flask_webgoat/ui.py`

The `/search` endpoint already used parameterized queries (`LIKE ?` with a tuple argument). No SQL injection present. No changes needed.

---

## 5. XSS & Other Code Vulnerabilities (Checked & Fixed)

### Finding 5a: Remote Code Execution

**Severity: CRITICAL**  
**File:** `flask_webgoat/actions.py`  
**OWASP:** A03:2021 - Injection

The `/grep_processes` endpoint passed user input into a shell command with `shell=True`, allowing arbitrary command execution.

**Before:**
```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

**After:**
```python
res = subprocess.run(
    ["ps", "aux"], capture_output=True,
)
out = res.stdout.decode("utf-8")
names = [line.split()[10] for line in out.splitlines() if name in line and len(line.split()) > 10]
```

`shell=True` is removed. The `ps` command runs without a shell, and filtering is done in Python.

### Finding 5b: Insecure Deserialization

**Severity: CRITICAL**  
**File:** `flask_webgoat/actions.py`  
**OWASP:** A08:2021 - Software and Data Integrity Failures

The `/deserialized_descr` endpoint used `pickle.loads()` on user-supplied base64 data, allowing arbitrary code execution via crafted pickle payloads.

**Before:**
```python
import pickle
deserialized = pickle.loads(data)
```

**After:**
```python
import json
deserialized = json.loads(data)
```

Pickle is replaced with JSON, which is a safe data format that cannot execute arbitrary code.

### Finding 5c: Directory Traversal

**Severity: HIGH**  
**File:** `flask_webgoat/actions.py`  
**OWASP:** A01:2021 - Broken Access Control

The `/message` endpoint concatenated user-supplied `filename` into a file path without sanitization, allowing writes outside the user's directory (e.g., `../../etc/passwd`).

**Before:**
```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

**After:**
```python
safe_name = Path(filename_param).name
filename = safe_name + ".txt"
path = (user_dir_path / filename).resolve()
if not str(path).startswith(str(user_dir_path.resolve())):
    return jsonify({"error": "invalid filename"}), 400
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

The filename is sanitized with `Path.name()` (strips directory components), and a resolved-path containment check ensures the final path stays within the user's directory.

### Finding 5d: Sensitive Data Exposure

**Severity: MEDIUM**  
**File:** `flask_webgoat/__init__.py`  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

The database connection had `conn.set_trace_callback(print)`, which printed all SQL queries (including passwords) to stdout, exposing sensitive data in logs.

**Fix:** The `set_trace_callback(print)` line was removed.

### Finding 5e: Broken Access Control (CORS)

**Severity: MEDIUM**  
**File:** `run.py`  
**OWASP:** A01:2021 - Broken Access Control

The `Access-Control-Allow-Origin` header was set to `*`, allowing any website to make cross-origin requests to the API.

**Before:**
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

**After:**
```python
response.headers['Access-Control-Allow-Origin'] = 'self'
```

### Finding 5f: Security Misconfiguration (CSP)

**Severity: MEDIUM**  
**File:** `run.py`  
**OWASP:** A05:2021 - Security Misconfiguration

The Content-Security-Policy allowed `'unsafe-inline'` scripts, weakening XSS defenses.

**Before:**
```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

**After:**
```python
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
```

### Finding 5g: XSS Review (No Critical Issue)

**Files:** `flask_webgoat/templates/search.html`, `flask_webgoat/templates/error.html`

Jinja2 templates use `{{ query }}` and `{{ message }}` to render user input. Flask enables Jinja2 auto-escaping for `.html` templates by default, so HTML special characters are escaped. No `|safe` filter or `{% autoescape false %}` directive was found. XSS risk is mitigated by auto-escaping. The improved CSP header (removing `'unsafe-inline'`) provides additional defense-in-depth.

---

## Summary of Changes

| File | Vulnerability | Severity | Status |
|------|--------------|----------|--------|
| `requirements.txt` | 22 CVEs in Flask, Werkzeug, Jinja2, click | CRITICAL | Fixed (all upgraded) |
| `flask_webgoat/__init__.py` | Hardcoded secret key | HIGH | Fixed (env var + random fallback) |
| `flask_webgoat/__init__.py` | Sensitive data exposure (SQL trace) | MEDIUM | Fixed (removed trace callback) |
| `flask_webgoat/auth.py` | SQL injection in login | CRITICAL | Fixed (parameterized query) |
| `flask_webgoat/auth.py` | Open redirect | MEDIUM | Fixed (URL validation) |
| `flask_webgoat/users.py` | SQL injection in create_user | CRITICAL | Fixed (parameterized query) |
| `flask_webgoat/actions.py` | Remote code execution (shell=True) | CRITICAL | Fixed (no shell, Python filtering) |
| `flask_webgoat/actions.py` | Insecure deserialization (pickle) | CRITICAL | Fixed (replaced with JSON) |
| `flask_webgoat/actions.py` | Directory traversal | HIGH | Fixed (filename sanitization + containment check) |
| `run.py` | Broken access control (CORS *) | MEDIUM | Fixed (restricted to self) |
| `run.py` | Security misconfiguration (CSP unsafe-inline) | MEDIUM | Fixed (strict CSP) |

---

## Verification

1. **Dependency scan:** `pip-audit -r requirements.txt` reports "No known vulnerabilities found" (exit 0)
2. **Application import:** `from flask_webgoat import create_app; create_app()` succeeds with updated dependencies
3. **Vulnerability markers:** All `# vulnerability:` comments removed from source code (remaining references are in README.md documentation only)

---

## Recommendations (Not Implemented)

These items are lower priority and were left unchanged to avoid altering application behavior beyond critical security fixes:

1. **Password hashing:** Passwords are stored in plaintext in SQLite. Use `werkzeug.security.generate_password_hash` / `check_password_hash`.
2. **Password policy:** Minimum password length of 3 is too weak. Increase to at least 8 characters.
3. **Rate limiting:** No rate limiting on login or API endpoints. Add `flask-limiter` to prevent brute-force attacks.
4. **HTTPS enforcement:** Add HSTS header and redirect HTTP to HTTPS in production.
5. **CSRF protection:** No CSRF tokens on POST forms. Add `flask-wtf` or similar CSRF protection.
6. **Session security:** Configure `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` for production deployments.
7. **Input validation:** Add explicit input length and format validation on all user-supplied parameters.
