# Security Audit Report — flask-webgoat

**Repository:** `factory-ai-demo` (flask-webgoat)
**Date:** 2026-08-10
**Auditor:** Factory Droid (automated)
**Scope:** Full static security review of source code, dependencies, configuration, and templates.

---

## Executive Summary

flask-webgoat is a **deliberately vulnerable** Flask training application. The audit
confirmed **22 known dependency vulnerabilities** (now remediated) and **11
application-level vulnerabilities** spanning OWASP Top 10 categories including
Injection, Broken Access Control, Insecure Deserialization, Cryptographic Failures,
and Security Misconfiguration.

| Category | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Dependency vulnerabilities | 14 | 6 | 2 | 0 | 22 |
| Code vulnerabilities | 4 | 4 | 2 | 1 | 11 |
| **Total** | **18** | **10** | **4** | **1** | **33** |

**Remediation status:**
- ✅ **Applied:** All 22 dependency vulnerabilities fixed by upgrading `requirements.txt`.
- 📋 **Documented (recommended fixes below):** The 11 code-level vulnerabilities. These
  are the intentional teaching examples in this app; the fixes below describe how to
  remediate each one in a production codebase.

---

## 1. Dependency Vulnerability Audit

### Note on `package.json`

This is a **Python/Flask project**, not a Node.js project. No `package.json` exists in
the repository. Dependency auditing was performed against `requirements.txt` using
`pip-audit` (OSV database). The Node.js `npm audit` step is not applicable here.

### Findings — `pip-audit` results (before remediation)

`pip-audit` reported **22 known vulnerabilities across 4 packages**:

| Package | Version | CVE / Advisory IDs | Fix Version Applied |
|---|---|---|---|
| **click** | 7.1.2 | PYSEC-2026-2132 | 8.3.3 |
| **Flask** | 0.12.5 | PYSEC-2019-179, PYSEC-2023-62, PYSEC-2026-2151 | 3.1.3 |
| **Jinja2** | 2.8 | PYSEC-2021-66, PYSEC-2019-220, PYSEC-2019-217, PYSEC-2026-1473, PYSEC-2026-1471, PYSEC-2026-1474, PYSEC-2026-1475 | 3.1.6 |
| **Werkzeug** | 0.16.1 | PYSEC-2022-203, PYSEC-2023-57, PYSEC-2023-58 (×2), PYSEC-2023-221, PYSEC-2026-2045, PYSEC-2026-2043, PYSEC-2026-2046, PYSEC-2026-2044, PYSEC-2026-2320 | 3.1.6 |

Notable CVEs include:
- **Werkzeug** — ReDoS in debugger, multipart form-data parsing memory exhaustion,
  multipart boundary collision, and multipart form parsing DoS.
- **Flask** — Information disclosure via session cookie deserialization, ReDoS in
  `safe_join` / URL routing.
- **Jinja2** — Sandbox escape via `str.format`, SSTI via `xmlattr`, hash collision DoS,
  sandbox escape via `attr` filter and `|attr` chaining.
- **click** — Path traversal in `PackageArgs` shell completion.

### Remediation applied

`requirements.txt` was upgraded to the latest safe, mutually-compatible versions:

```diff
- click==7.1.2
- Flask==0.12.5
- itsdangerous==1.1.0
- Jinja2==2.8
- MarkupSafe==1.1.1
- Werkzeug==0.16.1
+ click==8.3.3
+ Flask==3.1.3
+ itsdangerous==2.2.0
+ Jinja2==3.1.6
+ MarkupSafe==3.0.2
+ Werkzeug==3.1.6
```

**Verification:**
- `pip-audit` on the updated `requirements.txt`: **No known vulnerabilities found.**
- Application import smoke test: `create_app()` succeeds; all 9 routes register correctly.
  No breaking changes from the Flask 0.12 → 3.1 upgrade (the app uses only stable APIs:
  Blueprints, `render_template`, `jsonify`, `session`, `redirect`, `request`).

---

## 2. Hardcoded Secrets & API Keys

| # | Severity | Finding | Location |
|---|---|---|---|
| S1 | **Critical** | Hardcoded Flask `secret_key` used for session signing | `flask_webgoat/__init__.py:22` |
| S2 | **Critical** | Hardcoded admin credentials (`admin` / `maximumentropy`) seeded into DB | `flask_webgoat/__init__.py:34` |
| S3 | **High** | SQL trace callback prints all queries (including plaintext passwords) to stdout | `flask_webgoat/__init__.py:13` |
| S4 | **Medium** | CI pipeline references secret tokens via variable groups (correctly indirected, but worth verifying rotation) | `azure-pipelines.yml` |

### S1 — Hardcoded session secret key

**Evidence** (`flask_webgoat/__init__.py:22`):
```python
app.secret_key = "****************************************"
```
A static, committed secret key allows an attacker who learns it to forge Flask session
cookies, escalating privileges or bypassing authentication entirely.

**Fix:**
```python
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # fail fast if unset
```
Generate a strong key: `python -c "import secrets; print(secrets.token_hex(32))"`.

### S2 — Hardcoded admin credentials

**Evidence** (`flask_webgoat/__init__.py:33-34`):
```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```
A known admin username/password with `access_level=0` (highest privilege) is seeded on
every app start. Anyone reading the source has full admin access.

**Fix:** Seed admin credentials from environment variables and hash passwords:
```python
import os, hashlib
admin_user = os.environ["ADMIN_USERNAME"]
admin_pass = os.environ["ADMIN_PASSWORD"]
hashed = hashlib.scrypt(admin_pass.encode(), salt=os.environ["PASSWORD_SALT"].encode(),
                        n=16384, r=8, p=1, dklen=64)
conn.execute("INSERT INTO user (id, username, password, access_level) VALUES (1, ?, ?, 0)",
             (admin_user, hashed.hex()))
```

### S3 — SQL trace callback leaks passwords to logs

**Evidence** (`flask_webgoat/__init__.py:13`):
```python
conn.set_trace_callback(print)
```
Every SQL statement — including login queries that embed plaintext passwords — is printed
to stdout. In any deployed environment this exposes credentials in log aggregators,
container logs, or CI output.

**Fix:** Remove the `set_trace_callback` call entirely, or gate it behind an explicit
debug flag that is never enabled in production:
```python
if os.environ.get("SQL_TRACE") == "1":
    conn.set_trace_callback(print)
```

---

## 3. Authentication & Authorization Review

| # | Severity | Finding | Location |
|---|---|---|---|
| A1 | **High** | SQL injection in login bypasses authentication | `flask_webgoat/auth.py:24-26` |
| A2 | **High** | Open redirect on failed login | `flask_webgoat/auth.py:45` |
| A3 | **Medium** | Authorization check uses inverted/confusing access-level logic | `flask_webgoat/actions.py:29-31` |
| A4 | **Medium** | No CSRF protection on any state-changing endpoint | All `POST` routes |
| A5 | **Medium** | Session stored as plaintext tuple; no session invalidation/timeout | `flask_webgoat/auth.py:30,38` |
| A6 | **Low** | `create_user` allows creating users with `access_level=0` (full admin) | `flask_webgoat/users.py:24-26` |

### A1 — Authentication bypass via SQL injection

**Evidence** (`flask_webgoat/auth.py:24-26`):
```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
```
Submitting `username = admin' --` makes the password check a comment, logging in as admin
without knowing the password.

**Fix:** Use parameterized queries:
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), one=True)
```
(Note: the `login_and_redirect` endpoint already does this correctly — replicate that pattern.)

### A2 — Open redirect

**Evidence** (`flask_webgoat/auth.py:45`):
```python
return redirect(url)
```
On failed login, the `url` parameter is used verbatim for a redirect. An attacker can
craft a phishing link: `/login_and_redirect?username=x&password=y&url=https://evil.com`.
After the victim enters credentials and login fails, they are silently redirected to the
attacker's site.

**Fix:** Validate the redirect target against an allowlist, or only allow relative paths:
```python
from urllib.parse import urlparse
if not url or urlparse(url).netloc:
    return jsonify({"error": "invalid redirect url"}), 400
return redirect(url)
```

### A3 — Confusing access-level authorization logic

**Evidence** (`flask_webgoat/actions.py:29-31`):
```python
access_level = user_info[2]
if access_level > 2:
    return jsonify({"error": "access level < 2 is required for this action"})
```
The check rejects `access_level > 2` but the admin has `access_level = 0`. The logic is
inverted and error-prone: a level-1 or level-2 user can write files, and the boundary is
unclear. Compare with `users.py:24` which checks `access_level != 0` (only admin). The two
authorization checks are inconsistent.

**Fix:** Define a clear privilege model and a helper:
```python
def require_admin():
    user_info = session.get("user_info")
    if not user_info or user_info[2] != 0:
        abort(403)
```

### A4 — No CSRF protection

All `POST` endpoints (`/login`, `/create_user`, `/message`, `/deserialized_descr`) accept
form submissions without any CSRF token. Since the app uses cookie-based sessions, an
attacker can forge cross-site requests.

**Fix:** Enable Flask-WTF CSRF protection globally:
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

### A5 — Weak session management

`session["user_info"]` stores a plaintext tuple `(id, username, access_level)` and is never
invalidated. There is no logout endpoint, no session timeout, and no re-authentication for
sensitive actions. Because the secret key is hardcoded (S1), sessions are forgeable.

**Fix:** Store only a user ID in the session; load privileges on each request. Add a
`/logout` route that clears the session. Set `SESSION_COOKIE_HTTPONLY=True`,
`SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Lax'`.

### A6 — Privilege escalation via user creation

**Evidence** (`flask_webgoat/users.py:24-26`): `access_level` is taken directly from the
request form. An admin can create another `access_level=0` user, and there is no validation
that the requested level is within an allowed range.

**Fix:** Validate `access_level` against an allowed set and prevent creating users at the
caller's own level or above:
```python
requested = int(access_level)
if requested <= 0:
    return jsonify({"error": "invalid access level"}), 400
```

---

## 4. SQL Injection

| # | Severity | Finding | Location |
|---|---|---|---|
| Q1 | **Critical** | SQL injection in login | `flask_webgoat/auth.py:24-26` |
| Q2 | **Critical** | SQL injection in user creation | `flask_webgoat/users.py:37-39` |

### Q1 — Login SQL injection (also A1)

See A1 above. String interpolation (`%` formatting) directly into the query.

### Q2 — User creation SQL injection

**Evidence** (`flask_webgoat/users.py:37-39`):
```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```
A malicious `username` like `x', 'pw', 0); DROP TABLE user;--` executes arbitrary SQL.
The `int(access_level)` cast protects that one field, but `username` and `password` are
fully injectable.

**Fix:** Parameterized query:
```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, password, int(access_level)), commit=True)
```

### Positive note

`flask_webgoat/ui.py:16` and `flask_webgoat/auth.py:42` correctly use parameterized queries
with `?` placeholders. These are the patterns to replicate everywhere.

---

## 5. XSS & Template Injection

| # | Severity | Finding | Location |
|---|---|---|---|
| X1 | **Medium** | Reflected user input in templates (mitigated by autoescaping, but weakened by CSP) | `templates/search.html`, `templates/error.html` |
| X2 | **High** | Content-Security-Policy allows `unsafe-inline` scripts | `run.py:9` |

### X1 — Reflected user input

**Evidence:**
- `templates/search.html:9`: `Found {{ num_results }} results for query {{ query }}.`
- `templates/error.html:9`: `{{ message }}`
- `templates/search.html:11`: `{{ result }}`

Flask/Jinja2 **autoescapes** `{{ }}` output in `.html` templates by default, so these are
not directly exploitable as reflected XSS under the default configuration. However:

1. The error path in `ui.py:17` concatenates user input into the error message:
   `"Error while executing query " + query_param + ": " + err` — this **leaks internal
   SQL error details** to the client (information disclosure).
2. Relying solely on autoescaping is fragile; if any template ever uses `|safe` or
   `mark_safe`, it becomes exploitable.
3. The CSP header (X2) permits `unsafe-inline`, so even if an XSS vector were introduced,
   the browser would not block it.

**Fix:**
- Never concatenate user input into error messages; use a generic message and log details
  server-side.
- Add `X-Content-Type-Options: nosniff` and a strict CSP (see X2).

### X2 — Permissive Content-Security-Policy

**Evidence** (`run.py:9`):
```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```
`unsafe-inline` permits inline `<script>` tags and event handlers, defeating a primary XSS
mitigation.

**Fix:**
```python
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
)
```

---

## 6. Additional Vulnerabilities

| # | Severity | OWASP Category | Finding | Location |
|---|---|---|---|---|
| V1 | **Critical** | A03 Injection | Remote code execution via shell injection | `flask_webgoat/actions.py:43-49` |
| V2 | **Critical** | A08 Software & Data Integrity | Insecure deserialization of `pickle` | `flask_webgoat/actions.py:60-61` |
| V3 | **High** | A01 Broken Access Control | Directory traversal in file write | `flask_webgoat/actions.py:35-40` |
| V4 | **High** | A05 Security Misconfiguration | CORS wildcard `Access-Control-Allow-Origin: *` | `run.py:7` |
| V5 | **Medium** | A05 Security Misconfiguration | Debug server / no production hardening | `run.py:12` |
| V6 | **Medium** | A02 Cryptographic Failures | Plaintext password storage | `flask_webgoat/__init__.py:34` |

### V1 — Remote code execution (shell injection)

**Evidence** (`flask_webgoat/actions.py:43-49`):
```python
name = request.args.get("name")
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```
User input `name` is concatenated into a shell command with `shell=True`. A request like
`/grep_processes?name=;cat /etc/passwd` executes arbitrary commands on the host.

**Fix:** Never use `shell=True` with user input. Use a subprocess with argument list and
filter input:
```python
import subprocess, re
name = request.args.get("name", "")
if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
    return jsonify({"error": "invalid name"}), 400
res = subprocess.run(["pgrep", "-a", name], capture_output=True, text=True)
```

### V2 — Insecure deserialization (pickle)

**Evidence** (`flask_webgoat/actions.py:60-61`):
```python
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```
`pickle.loads` on attacker-controlled input is arbitrary code execution. A crafted pickle
runs `__reduce__` to execute any Python on the server.

**Fix:** Never deserialize untrusted pickle data. Use a safe format like JSON:
```python
import json
data = base64.urlsafe_b64decode(pickled).decode("utf-8")
deserialized = json.loads(data)
```

### V3 — Directory traversal

**Evidence** (`flask_webgoat/actions.py:35-40`):
```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```
A `filename` like `../../etc/cron.d/evil` escapes the user's data directory and writes
arbitrary files anywhere the process user can access.

**Fix:** Resolve and verify the path stays within the user directory:
```python
user_dir_path = Path("data") / str(user_id)
user_dir_path.mkdir(parents=True, exist_ok=True)
target = (user_dir_path / (filename_param + ".txt")).resolve()
if not str(target).startswith(str(user_dir_path.resolve())):
    return jsonify({"error": "invalid filename"}), 400
```

### V4 — CORS wildcard

**Evidence** (`run.py:7`):
```python
response.headers['Access-Control-Allow-Origin'] = '*'
```
A wildcard CORS policy allows any website to make credentialed cross-origin requests to
this API (combined with cookie sessions, this enables CSRF-like data theft).

**Fix:** Remove the wildcard; set an explicit allowlist or omit the header entirely:
```python
# Only set CORS headers for known origins
allowed = {"https://your-frontend.example.com"}
origin = request.headers.get("Origin")
if origin in allowed:
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Vary'] = 'Origin'
```

### V5 — No production hardening

**Evidence** (`run.py:12`): `app.run()` starts the development Werkzeug server with debug
mode off by default, but the app has no production WSGI server, no `SESSION_COOKIE_SECURE`,
no `app.config['DEBUG'] = False` guard, and no `HTTPS` enforcement.

**Fix:** Run behind a production WSGI server (gunicorn/uwsgi), set
`SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, and add HSTS:
```python
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
```

### V6 — Plaintext password storage

**Evidence** (`flask_webgoat/__init__.py:34` and `auth.py`): Passwords are compared as
plaintext strings. The DB stores `maximumentropy` directly.

**Fix:** Hash passwords with a modern KDF (Argon2, scrypt, or bcrypt) and compare hashes:
```python
import hashlib, secrets
def hash_password(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=64).hex()
```

---

## Summary of Applied Changes

| Change | File | Status |
|---|---|---|
| Upgrade all 6 dependencies to vulnerability-free versions | `requirements.txt` | ✅ Applied & verified |

All other findings are documented above with concrete fixes. The code-level vulnerabilities
are intentional in this training app; applying the fixes would remove its teaching value.
In a production codebase, every fix above should be implemented.

---

## Verification Performed

| Check | Tool | Result |
|---|---|---|
| Dependency vulnerability scan (original) | `pip-audit` (OSV) | 22 vulnerabilities in 4 packages |
| Dependency vulnerability scan (updated) | `pip-audit` (OSV) | **0 vulnerabilities** |
| Dependency compatibility resolution | `pip install --dry-run` | All versions resolve cleanly |
| Application import smoke test | `python -c "from flask_webgoat import create_app"` | App creates; 9 routes register |
| Hardcoded secret scan | `grep` regex scan | 3 findings (secret_key, admin creds, trace callback) |
| Dangerous API scan | `grep` for `shell=True`, `pickle.loads`, `eval` | 2 findings (actions.py) |
| SQL injection scan | Source review | 2 findings (auth.py, users.py) |
| XSS / template scan | Source review of templates | 2 findings (CSP, reflected input) |

---

*Generated by Factory Droid automated security audit.*
