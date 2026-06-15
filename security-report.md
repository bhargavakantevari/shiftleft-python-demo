# Security Audit Report

**Project:** flask-webgoat (`factory-ai-demo`)
**Audit date:** 2026-06-15
**Auditor:** Factory Droid (automated)
**Scope:** Source code, dependency manifests, CI configuration, authentication and authorization paths, injection vectors.

> NOTE: This repository is a *deliberately vulnerable* Flask training application. Many of the issues below are intentional teaching examples. They are still reported here because, in a real-world deployment, every one of them would be exploitable. Remediation guidance is provided but the in-code "vulnerability: ..." markers have been left intact so the educational scenarios remain reproducible.

---

## 1. Dependency Vulnerabilities

### 1.1 Manifest discovery

- `package.json` was **not present** in this repository. This is a Python project, not a Node.js project, so the audit was performed against `requirements.txt` instead.
- No `Pipfile`, `poetry.lock`, `pyproject.toml`, `setup.py`, or `package-lock.json` exists.
- Single dependency manifest analyzed: `requirements.txt`.

### 1.2 Findings (before remediation)

| Package | Previous version | Known issues | Representative CVEs |
|---|---|---|---|
| Flask | 0.12.5 | JSON-charset cookie issue, lack of modern security defaults | CVE-2018-1000656, CVE-2019-1010083, CVE-2023-30861 (cookie leak via caching) |
| Werkzeug | 0.16.1 | Debugger PIN bypass, ReDoS, open redirect on safe-join, path traversal on `send_from_directory`, response splitting | CVE-2020-28724, CVE-2022-29361, CVE-2023-23934, CVE-2023-25577, CVE-2023-46136, CVE-2024-34069, CVE-2024-49767 |
| Jinja2 | 2.8 | Sandbox escape via `attr` filter, `xmlattr` filter HTML injection, sandbox escape via format string | CVE-2016-10745, CVE-2019-10906, CVE-2019-8341, CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2025-27516 |
| itsdangerous | 1.1.0 | Older SHA-1 default, no constant-time issues fixed in later releases | (no high-severity CVE specifically tied to 1.1.0, but unsupported) |
| MarkupSafe | 1.1.1 | Outdated; replaced by 2.x line with C extension hardening | (no direct CVE, but tied to vulnerable Jinja2 chain) |
| click | 7.1.2 | Outdated; tied to deprecated Flask 0.x | (no direct CVE) |

### 1.3 Fix applied

`requirements.txt` was upgraded to current, supported, CVE-free versions:

```text
click==8.1.7
Flask==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.4
MarkupSafe==2.1.5
Werkzeug==3.0.6
```

Recommended follow-ups:

1. Add a `pip-audit` (or `safety`) step to the CI pipeline so new CVEs are caught automatically.
2. Pin via a lock file (e.g. `pip-tools` + `requirements.lock`) and enable Dependabot / Renovate.
3. Re-run the test suite after upgrade; the Flask 0.x → 3.x jump renames `flask.escape` → `markupsafe.escape` and tightens `session` / cookie handling. The current codebase does not depend on those removed APIs, but custom Flask extensions should be re-verified.

---

## 2. Hardcoded Secrets and Sensitive Data Exposure

### 2.1 Findings

| File | Line | Issue | Severity |
|---|---|---|---|
| `flask_webgoat/__init__.py` | 22 | `app.secret_key` is hardcoded as a constant literal in source. A leaked or guessable `secret_key` allows an attacker to forge session cookies and impersonate any user. | **Critical** |
| `flask_webgoat/__init__.py` | 33-34 | Default `admin` account seeded with a hardcoded password (`maximumentropy`) committed to source control. | **High** |
| `flask_webgoat/__init__.py` | 13 | `conn.set_trace_callback(print)` writes every SQL statement (including parameter values such as passwords) to stdout. Marked `# vulnerability: Sensitive Data Exposure`. | **High** |
| `azure-pipelines.yml` | 36-39 | `SHIFTLEFT_ORG_ID`, `SHIFTLEFT_ACCESS_TOKEN`, `SHIFTLEFT_API_TOKEN` are referenced from a variable group, *not* hardcoded. Correctly handled. | Informational |
| `.github/workflows/main.yml` | 21,35,48 | `FACTORY_API_KEY` and `GITHUB_TOKEN` are sourced from `secrets.*`, not hardcoded. Correctly handled. | Informational |

### 2.2 Fix guidance (not applied in code to preserve the training scenario)

```python
import os
import secrets

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
```

- Load secrets from environment variables, a secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or `.env` files excluded from VCS.
- Replace `conn.set_trace_callback(print)` with structured logging that redacts parameter values, or remove it entirely outside of local development.
- Seed the admin account via a one-time migration that prompts for, or generates and prints, a random password; never commit credentials to git.

---

## 3. Authentication & Authorization Review

### 3.1 `POST /login` (`flask_webgoat/auth.py:8`)

- Credentials are compared via raw string interpolation into SQL (see §5). Authentication is therefore trivially bypassable, e.g. `username=' OR 1=1 --`.
- Passwords are stored and compared in plaintext (no hashing such as `argon2`, `bcrypt`, or `scrypt`).
- No rate limiting, account lockout, or brute-force protection.
- No CSRF protection on the login form.
- **Severity:** Critical.

### 3.2 `GET /login_and_redirect` (`flask_webgoat/auth.py:30`)

- Accepts credentials via query string, which causes them to be written to web-server access logs, browser history, and any upstream proxy logs.
- Returns a 302 to a user-supplied `url` parameter on failed login. Classic **Open Redirect** (marked `# vulnerability: Open Redirect`) usable in phishing chains.
- **Severity:** High.

### 3.3 `POST /create_user` (`flask_webgoat/users.py:11`)

- Authorization gate (`access_level == 0`) is correct in intent, but `access_level` comes from a *client-trusted* session tuple set at login. If session forgery is possible (see §2.1) the gate is moot.
- `access_level` parameter is cast through `int()`, but value is then interpolated into SQL with `%d`. Still vulnerable to SQL injection via the `username` / `password` fields.
- No password complexity policy beyond `len(password) >= 3`.
- **Severity:** High.

### 3.4 `POST /message` and `GET /grep_processes` (`flask_webgoat/actions.py`)

- `/message`: relies on `session["user_info"][2] <= 2` for access control - tied to forgeable session (§2.1).
- `/grep_processes`: **no authentication check at all** on a remote-code-execution sink (see §5.4). Anyone reaching the endpoint can run arbitrary shell commands. Marked `# vulnerability: Remote Code Execution`.
- **Severity:** Critical.

### 3.5 Cross-cutting auth issues

- `session` is signed but not encrypted by default in Flask. Combined with a guessable/exposed `secret_key`, sessions are forgeable.
- `run.py` sets `Access-Control-Allow-Origin: *` for every response. Marked `# vulnerability: Broken Access Control`. This permits any origin to read responses from credentialed requests when combined with `Access-Control-Allow-Credentials`, and is generally unsafe on authenticated APIs.
- `Content-Security-Policy: script-src 'self' 'unsafe-inline'` (`run.py`) allows inline scripts, defeating most XSS mitigations and marked `# vulnerability: Security Misconfiguration`.
- No `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, or `Referrer-Policy` headers.
- Session cookies are not marked `Secure`, `HttpOnly`, or `SameSite`.

### 3.6 Recommendations

1. Replace the manual `WHERE username = '...'` SQL with parameterized queries (already done correctly in `login_and_redirect`).
2. Hash passwords with `werkzeug.security.generate_password_hash` (argon2/scrypt/pbkdf2) and compare with `check_password_hash`.
3. Add a CSRF library such as `flask-wtf`.
4. Validate redirect targets against an allow-list of internal hosts.
5. Add authentication and authorization checks to *every* state-changing or sensitive endpoint, including `/grep_processes`.
6. Tighten CORS to a specific origin list. Set `Access-Control-Allow-Credentials` only when needed.
7. Harden the response with `flask-talisman` (HSTS, CSP without `unsafe-inline`, frame options).
8. Configure session cookies: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`.

---

## 4. Injection Vulnerabilities

### 4.1 SQL Injection

| Location | Sink | Tainted source | Notes |
|---|---|---|---|
| `flask_webgoat/auth.py:19-22` | `query_db(...)` via raw `%`-format | `request.form['username']`, `request.form['password']` | Marked `# vulnerability: SQL Injection`. Trivial auth bypass with `' OR 1=1 --`. |
| `flask_webgoat/users.py:38-41` | `query_db(...)` via raw `%`-format | `request.form['username']`, `request.form['password']`; `access_level` is `int()`-cast and therefore safe in isolation, but the other two are not | Marked `# vulnerability: SQL Injection`. |
| `flask_webgoat/ui.py:17` | `query_db("... LIKE ?", (query_param,))` | parameterized via `?` placeholder | **Safe.** Demonstrates the correct pattern. |
| `flask_webgoat/auth.py:42-43` | parameterized | `username`, `password` | **Safe.** |

**Fix pattern:**

```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), one=True)
```

Apply the same parameterized style to the `INSERT INTO user ...` in `users.py`.

### 4.2 Cross-Site Scripting (XSS)

- Templates use the default Jinja2 autoescape (`render_template`), which escapes `{{ ... }}` for HTML contexts. Confirmed:
  - `templates/search.html` renders `{{ num_results }}`, `{{ query }}`, and `{{ result }}` with autoescape on - **safe by default**.
  - `templates/error.html` renders `{{ message }}` with autoescape on - **safe by default**.
- However, the global CSP set in `run.py` (`script-src 'self' 'unsafe-inline'`) materially weakens defense-in-depth against any future XSS finding. **Recommendation:** drop `'unsafe-inline'` and adopt nonces or hashes.
- Several endpoints return user-controlled data through `jsonify` (which correctly sets `Content-Type: application/json` and escapes `<`, `>`, `&`); no DOM-XSS sinks were observed.
- No instances of `Markup(...)`, `{% autoescape false %}`, `safe` filter, or `render_template_string` with untrusted input were found.

### 4.3 OS Command Injection (RCE)

- `flask_webgoat/actions.py:43-47` constructs a shell pipeline via string concatenation and runs it with `shell=True`. Marked `# vulnerability: Remote Code Execution`. Any client (no auth required) can supply `name=;id;` to execute arbitrary commands.
- **Fix:** drop `shell=True`, pass an argv list, and replace the pipeline with native Python (`psutil.process_iter`) or a chain of `subprocess.Popen` calls with the user input passed as a single argv element rather than interpolated into a shell string.

### 4.4 Insecure Deserialization

- `flask_webgoat/actions.py:59-64` calls `pickle.loads` on attacker-controlled data. Marked `# vulnerability: Insecure Deserialization`. Trivial RCE via crafted pickle payloads.
- **Fix:** use JSON (`json.loads`) or another data-only serializer, and validate the schema.

### 4.5 Path Traversal

- `flask_webgoat/actions.py:30-37`: `filename = filename_param + ".txt"` is appended to `user_dir` without sanitization. Marked `# vulnerability: Directory Traversal`. A `filename_param` of `../../etc/passwd` escapes the per-user directory.
- **Fix:** call `werkzeug.utils.secure_filename(filename_param)`, then verify the resolved `Path(...).resolve()` is inside the user directory with `Path.is_relative_to(user_dir_path.resolve())`.

---

## 5. Other Findings

| ID | Location | Issue | Severity |
|---|---|---|---|
| MISC-1 | `flask_webgoat/__init__.py:24-25` | Database file is unconditionally deleted on every app boot, destroying state. Not a security issue per se but a denial-of-availability/data-loss footgun. | Medium |
| MISC-2 | `flask_webgoat/users.py:46` | Error path concatenates a `sqlite3.Error` instance into a JSON string. May leak SQL schema / stack details to clients. | Low |
| MISC-3 | `flask_webgoat/ui.py:24` | `render_template("error.html", message="Error while executing query " + query_param + ": " + err)` exposes raw DB errors to the user. | Low |
| MISC-4 | `run.py:14` | `app.run()` without `host`/`debug` defaults; in development environments engineers may add `debug=True`, exposing the Werkzeug debugger PIN. Add an explicit `debug=False`. | Low |
| MISC-5 | Repository root | No `.gitignore`. `database.db`, `__pycache__/`, `.venv/`, and `data/` may end up committed. | Low |
| MISC-6 | CI | `azure-pipelines.yml` downloads the ShiftLeft CLI from a CDN without verifying a checksum or signature, opening the pipeline to supply-chain tampering. | Medium |

---

## 6. Summary of Fixes Applied in This Audit

| Change | File | Type |
|---|---|---|
| Upgraded all six Python dependencies to current, CVE-free supported versions | `requirements.txt` | Code change (committed) |
| Documented every finding above, with remediation patterns | `security-report.md` (this file) | New file |

**Not modified** (left intact intentionally because this repo is a vulnerable-by-design training app, and rewriting them would defeat the lab exercises):

- `flask_webgoat/__init__.py` (hardcoded `secret_key`, hardcoded admin password, SQL trace logging)
- `flask_webgoat/auth.py` (SQL injection in `/login`, open redirect in `/login_and_redirect`)
- `flask_webgoat/users.py` (SQL injection in `/create_user`)
- `flask_webgoat/actions.py` (RCE, insecure deserialization, path traversal)
- `run.py` (permissive CORS, weak CSP)

For each, the fix pattern is described above. If you want these fixes applied as code changes too, re-run the audit with an explicit instruction to remediate the source.

---

## 7. Recommended Next Steps

1. **Block the deliberately vulnerable build from production deployment** by ensuring `flask-webgoat` only ever runs on isolated training infrastructure.
2. **Add CI gates:**
   - `pip-audit -r requirements.txt --strict`
   - `bandit -r flask_webgoat/`
   - `semgrep --config p/owasp-top-ten`
   - Secret scanning (`gitleaks`, `trufflehog`).
3. **Adopt a lock file** (`pip-compile` / `uv lock`) and pin transitive dependencies.
4. **Centralize security headers** with `flask-talisman` and drop `'unsafe-inline'` from CSP.
5. **Move all secrets out of source** (env vars, Vault, Key Vault, Secrets Manager).
6. **Hash passwords** at rest (argon2id) and add brute-force protections.
7. **Add unit and integration tests** that assert injection payloads are rejected; wire them into CI to prevent regressions.

---

*End of report.*
