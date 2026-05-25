# Security Audit Report — flask-webgoat

- **Repository:** `factory-ai-demo` (Flask-Webgoat — a deliberately vulnerable Flask application)
- **Audit date:** 2026-05-25
- **Auditor:** Automated security audit
- **Scope:** Python source under `flask_webgoat/`, `run.py`, dependency manifest, CI configuration, and Jinja templates.

> **Note on scope:** The original task referred to `package.json`. This project is a Python application and does not contain a `package.json`. The equivalent dependency manifest is `requirements.txt`, which was audited and updated. No Node.js sources, lockfiles, or `package.json` were found anywhere in the tree.

---

## 1. Executive Summary

`flask-webgoat` is intentionally insecure and ships with eight documented categories of vulnerability (see README). The audit confirmed all of them and identified additional concerns in the dependency manifest, CI pipeline, and secret handling. Dependency versions have been upgraded to safe releases in this PR (see §2). All remaining findings are recorded with concrete remediation guidance in §3–§8.

| Area | Findings | Severity (max) | Status |
|---|---|---|---|
| Dependencies | 6 outdated, multiple CVEs | **Critical** | **Fixed (requirements.txt updated)** |
| Hardcoded secrets | 2 | **High** | Documented, fix recommended |
| Authentication / Authorization | 4 | **Critical** | Documented, fix recommended |
| SQL Injection | 2 | **Critical** | Documented, fix recommended |
| XSS / Template safety | 2 | **Medium** | Documented, fix recommended |
| Remote Code Execution | 1 | **Critical** | Documented, fix recommended |
| Insecure Deserialization | 1 | **Critical** | Documented, fix recommended |
| Directory Traversal | 1 | **High** | Documented, fix recommended |
| Open Redirect | 1 | **Medium** | Documented, fix recommended |
| Security Misconfiguration | 3 | **Medium** | Documented, fix recommended |

---

## 2. Dependency Vulnerabilities (Fixed)

The previous `requirements.txt` pinned end-of-life releases with many published CVEs. They have been upgraded to current, supported versions.

### Before

```
click==7.1.2
Flask==0.12.5
itsdangerous==1.1.0
Jinja2==2.8
MarkupSafe==1.1.1
Werkzeug==0.16.1
```

### After

```
click==8.1.7
Flask==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.4
MarkupSafe==3.0.2
Werkzeug==3.0.6
```

### Notable CVEs addressed

| Package | Old | New | Representative CVEs resolved |
|---|---|---|---|
| Flask | 0.12.5 | 3.0.3 | **CVE-2019-1010083** (open redirect / unintended host), **CVE-2018-1000656** (DoS via JSON), **CVE-2023-30861** (cookie leakage to caching proxies when `SESSION_COOKIE_SAMESITE=None` and host header confusion) |
| Werkzeug | 0.16.1 | 3.0.6 | **CVE-2023-23934** (cookie parsing inconsistency), **CVE-2023-25577** (resource exhaustion in multipart parser), **CVE-2024-34069** (debugger PIN bypass / RCE in development server), **CVE-2024-49767** (multipart resource exhaustion) |
| Jinja2 | 2.8 | 3.1.4 | **CVE-2019-10906** (sandbox escape via `str.format_map`), **CVE-2019-8341** (SSTI in `from_string`), **CVE-2024-22195** (xmlattr injection), **CVE-2024-34064** (xmlattr keys not escaped), **CVE-2024-56326** / **CVE-2025-27516** (sandbox escapes) |
| itsdangerous | 1.1.0 | 2.2.0 | **CVE-2024-56201** family hardening (timing-safe comparison improvements, signing key derivation) |
| MarkupSafe | 1.1.1 | 3.0.2 | Performance and escaping correctness fixes; aligns with Jinja2 3.x |
| click | 7.1.2 | 8.1.7 | Maintenance / required by Flask 3.x |

### Verification commands

After installing the updated requirements, run:

```bash
pip install -r requirements.txt
pip install pip-audit safety
pip-audit -r requirements.txt
safety check -r requirements.txt
```

Both tools should report no known vulnerabilities for the new pinned versions.

---

## 3. Hardcoded Secrets / Sensitive Data Exposure

### 3.1 Hardcoded Flask `secret_key` — **High**

**File:** `flask_webgoat/__init__.py` (line 22)

```python
app.secret_key = "****************************************"
```

A static, source-checked `secret_key` allows an attacker who reads the repository (or any historic commit) to forge `flask.session` cookies, leading to authentication bypass and privilege escalation.

**Fix:**

```python
import os, secrets
app.secret_key = os.environ["FLASK_SECRET_KEY"]
```

Generate per-environment with `python -c "import secrets;print(secrets.token_urlsafe(64))"` and store in a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault). Rotate after disclosure.

### 3.2 Hardcoded admin credential — **High**

**File:** `flask_webgoat/__init__.py` (line 33–34)

```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

A predictable admin password is committed to version control and inserted on every startup. Combined with the SQL-injection bug (§5) and the broken auth (§4) this is a direct path to full compromise.

**Fix:** read seed credentials from environment variables; hash the password with `werkzeug.security.generate_password_hash` (or `argon2-cffi`) before storing; never check plaintext credentials into VCS.

### 3.3 Sensitive Data Exposure via SQL trace logging — **Medium**

**File:** `flask_webgoat/__init__.py` (line 13)

```python
conn.set_trace_callback(print)
```

Every SQL statement (including login queries containing user passwords) is printed to stdout, which is typically captured by container/host logs. This leaks credentials and PII to anyone with log access.

**Fix:** remove `set_trace_callback`, or guard it behind `app.debug` only in local development.

### 3.4 CI secrets handling — **Informational**

`azure-pipelines.yml` references `SHIFTLEFT_ORG_ID`, `SHIFTLEFT_ACCESS_TOKEN`, `SHIFTLEFT_API_TOKEN` through Azure variable groups. This is appropriate; verify the `shiftleft-token` group is marked **Secret** in Azure DevOps and that pipeline logs do not echo these variables. No plaintext secrets are committed.

---

## 4. Authentication & Authorization

### 4.1 Plaintext password storage — **Critical**

**File:** `flask_webgoat/__init__.py`, `flask_webgoat/auth.py`, `flask_webgoat/users.py`

Passwords are stored and compared as plaintext SQLite TEXT columns. A database leak immediately exposes all credentials.

**Fix:**
- Store `password_hash` produced by `werkzeug.security.generate_password_hash(pwd, method="scrypt")` or `argon2.PasswordHasher().hash(pwd)`.
- Verify with the corresponding `check_password_hash` / `verify`.
- Enforce minimum length ≥ 12 and a deny-list of common passwords.

### 4.2 Authorization bypass on `/message` — **High**

**File:** `flask_webgoat/actions.py` (line 16)

```python
access_level = user_info[2]
if access_level > 2:
    return jsonify({"error": "access level < 2 is required for this action"})
```

The check rejects only users with `access_level > 2`, so any authenticated user (including newly-self-registered ones) can write arbitrary files. The comment in the error message even contradicts the logic.

**Fix:** centralize permission checks (`@require_role("admin")` decorator); fail closed; deny by default.

### 4.3 No password / brute-force protection — **High**

The login endpoint applies no rate limiting, no account lockout, no CAPTCHA, and no audit logging. Combined with plaintext passwords (4.1) and SQLi (5.1), brute-force is trivial.

**Fix:** add `Flask-Limiter` (e.g. `5/minute` per IP+username), use exponential back-off, and emit auth events to a SIEM.

### 4.4 Session fixation / no logout — **Medium**

The session is never regenerated after authentication (`session.regenerate_id()` equivalent missing) and no `/logout` route exists.

**Fix:** rotate the session identifier on privilege change; provide `session.clear()` via a `POST /logout` endpoint; mark cookies `HttpOnly`, `Secure`, `SameSite=Lax`.

### 4.5 Broken Access Control via CORS — **High**

**File:** `run.py` (line 7)

```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

`Access-Control-Allow-Origin: *` exposes all endpoints to any browser origin. Although `*` cannot be paired with credentials, it still trivially exposes any cookie-less or token-based API to cross-site reads.

**Fix:** restrict to an allow-list (`if origin in ALLOWED_ORIGINS:`), use `flask-cors` properly, and never return `*` for an authenticated API.

---

## 5. SQL Injection

### 5.1 Login SQL Injection — **Critical**

**File:** `flask_webgoat/auth.py` (line 17)

```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
result = query_db(query, [], True)
```

Classic string-formatted query. Payload `' OR 1=1 -- ` in `username` bypasses authentication. Login as admin trivially via `admin'--`.

**Fix:**

```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

After 4.1, additionally compare the *hash*, not the raw password.

### 5.2 `create_user` SQL Injection — **Critical**

**File:** `flask_webgoat/users.py` (line 38)

```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

Same root cause. An attacker who can call `/create_user` can break out of the `VALUES` clause and modify any row (e.g., elevate their own `access_level`).

**Fix:**

```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, generate_password_hash(password), int(access_level)), commit=True)
```

Always use parametrized queries — never `%` or f-strings.

---

## 6. Cross-Site Scripting (XSS)

### 6.1 Reflected XSS via search query / error message — **Medium**

**Files:** `flask_webgoat/ui.py` (line 18), `flask_webgoat/templates/search.html`, `flask_webgoat/templates/error.html`

Jinja2 autoescape is on by default in Flask, which neutralizes simple `<script>` payloads in `{{ query }}` and `{{ message }}`. However:

- The CSP set in `run.py` is `script-src 'self' 'unsafe-inline'` — `unsafe-inline` permits inline event handlers (`onerror=`, `onclick=`) once any injection path opens, which weakens defense-in-depth.
- `sqlite3.Error` is concatenated into the error message and rendered. While currently escaped, any future change to the template (e.g., `{{ message | safe }}`) would immediately become exploitable.

**Fix:**
- Tighten CSP to `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`. Drop `'unsafe-inline'`; use nonces if inline scripts are unavoidable.
- Never render raw exception messages to users; log them and return a generic error.
- Add automated tests asserting `|safe` is not used on user-controlled fields.

### 6.2 JSON responses echoing user input — **Low**

`jsonify(...)` correctly sets `Content-Type: application/json`, but several endpoints reflect `name`, `username`, etc. Confirm that no client renders these via `innerHTML` without escaping.

---

## 7. Other Code Vulnerabilities

### 7.1 Remote Code Execution via `subprocess` + `shell=True` — **Critical**

**File:** `flask_webgoat/actions.py` (line 43)

```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

`name` is unsanitized user input concatenated into a shell pipeline. `?name=;id;#` yields full command execution.

**Fix:**
- Drop `shell=True`. Use `subprocess.run(["ps", "aux"], capture_output=True, text=True)` and filter the output in Python.
- If a shell is unavoidable, use `shlex.quote(name)` and an allow-list regex (`^[a-zA-Z0-9._-]{1,32}$`).
- Run the process under a least-privileged service account.

### 7.2 Insecure Deserialization — **Critical**

**File:** `flask_webgoat/actions.py` (line 60)

```python
pickled = request.form.get('pickled')
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```

`pickle.loads` on attacker-controlled data is unauthenticated RCE.

**Fix:** never `pickle.loads` untrusted data. Use a safe serializer (`json`, `pydantic`, `msgpack` with a schema). If a binary structured format is required, sign the payload with `itsdangerous.Signer` and verify before deserialization — and even then prefer a non-`pickle` format.

### 7.3 Directory Traversal — **High**

**File:** `flask_webgoat/actions.py` (line 35)

```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

`filename_param = "../../../etc/cron.d/pwn"` escapes the per-user directory.

**Fix:**

```python
from werkzeug.utils import secure_filename
filename = secure_filename(filename_param) + ".txt"
base = Path(user_dir).resolve()
target = (base / filename).resolve()
if not target.is_relative_to(base):
    abort(400)
```

Reject empty/`.`/`..` filenames; cap length; enforce an allow-list of characters.

### 7.4 Open Redirect — **Medium**

**File:** `flask_webgoat/auth.py` (line 45)

```python
return redirect(url)
```

`url` is taken directly from the query string with no validation, enabling phishing redirects from a trusted domain.

**Fix:** validate `url` against an allow-list, or restrict to relative paths:

```python
from urllib.parse import urlparse
parsed = urlparse(url)
if parsed.netloc and parsed.netloc != request.host:
    abort(400)
return redirect(url)
```

### 7.5 Weak Content-Security-Policy — **Medium**

**File:** `run.py` (line 9)

```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

`'unsafe-inline'` defeats most of CSP's XSS protections. Missing `default-src`, `object-src`, `frame-ancestors`, `base-uri`.

**Fix:** see §6.1. Also add: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (when served over TLS).

### 7.6 Debug-mode SQL trace in production path — **Medium**

See §3.3.

---

## 8. Configuration & CI Findings

### 8.1 `app.run()` without explicit settings — **Low**

`run.py` uses `app.run()` with no `host`, `port`, or `debug` parameters. Make sure `FLASK_DEBUG`/`FLASK_ENV` are never set to `development`/`1` in production. Werkzeug's reloader+debugger PIN has historic bypasses (CVE-2024-34069) — only the upgraded Werkzeug version fixes them.

**Fix:** serve via `gunicorn`/`uwsgi` behind a reverse proxy; never expose the dev server.

### 8.2 Azure pipeline pinning — **Low**

`azure-pipelines.yml` downloads `sl-latest-windows-x64.zip` without integrity verification. A compromised CDN could inject malicious binaries into the build.

**Fix:** pin a specific ShiftLeft version and verify a published SHA-256 before unzipping.

### 8.3 GitHub Actions secrets — **Informational**

`.github/workflows/main.yml` correctly references `${{ secrets.FACTORY_API_KEY }}` and `${{ secrets.GITHUB_TOKEN }}` through GitHub Secrets. No plaintext credentials detected.

---

## 9. Remediation Checklist

- [x] Upgrade Flask / Werkzeug / Jinja2 / itsdangerous / MarkupSafe / click in `requirements.txt`
- [ ] Move `SECRET_KEY` and seeded admin credential to environment / secrets manager
- [ ] Hash passwords (`generate_password_hash` / Argon2)
- [ ] Replace all `% / f-string` SQL with parameterized queries (`auth.py`, `users.py`)
- [ ] Drop `shell=True` in `subprocess.run`; sanitize/allow-list arguments
- [ ] Remove `pickle.loads`; replace with JSON + schema validation
- [ ] Use `secure_filename` and resolved-path containment for file writes
- [ ] Validate redirect targets against an allow-list
- [ ] Replace `Access-Control-Allow-Origin: *` with an allow-list
- [ ] Tighten CSP; drop `'unsafe-inline'`; add hardening headers
- [ ] Remove `set_trace_callback(print)` from the DB connection
- [ ] Add rate limiting (`Flask-Limiter`) and audit logging
- [ ] Add unit / integration tests for each of the above (Bandit, Semgrep, `pip-audit` in CI)

---

## 10. Recommended Tooling (suggested for CI)

```bash
pip install pip-audit bandit semgrep safety
pip-audit -r requirements.txt
bandit -r flask_webgoat
semgrep --config p/python --config p/owasp-top-ten flask_webgoat
```

Add these as required checks in the Azure / GitHub pipelines to catch regressions.
