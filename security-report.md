# Security Audit Report — `flask-webgoat`

**Audit date:** 2026-05-11
**Auditor:** Droid (Factory AI)
**Repository:** factory-ai-demo (master)
**Scope:** Full repository — application code, dependencies, CI/CD pipeline,
templates, and configuration.

> **Project note:** `flask-webgoat` is a deliberately-vulnerable training
> application. The application-level findings below are intentional and are
> documented for completeness; only the dependency-level vulnerabilities have
> been remediated in this audit so that the training vulnerabilities remain
> demonstrable. Each application finding includes a recommended fix.

---

## 1. Executive summary

| Category | Findings | Status |
|---|---|---|
| Vulnerable dependencies | 6 packages, 25+ historical CVEs | **Fixed** (requirements.txt upgraded) |
| Hardcoded secrets / credentials | 3 (secret_key, admin password, debug trace) | Documented (intentional) |
| Authentication / authorization weaknesses | 4 | Documented (intentional) |
| Injection vulnerabilities (SQLi / RCE / Deserialization) | 5 | Documented (intentional) |
| Path / Open-redirect issues | 2 | Documented (intentional) |
| XSS / template handling | 1 | Documented (intentional) |
| Security misconfiguration (CORS, CSP, debug) | 2 | Documented (intentional) |
| CI/CD pipeline issues | 1 minor | Documented |

> Note: There is **no `package.json`** in this repository — the project is
> Python/Flask, so the dependency audit was performed against
> `requirements.txt` using `pip-audit` (PyPI / OSV advisory database).

---

## 2. Dependency vulnerabilities (FIXED)

### 2.1 Previous `requirements.txt`

```
click==7.1.2
Flask==0.12.5
itsdangerous==1.1.0
Jinja2==2.8
MarkupSafe==1.1.1
Werkzeug==0.16.1
```

All six packages were several major versions behind the current secure
releases. Notable CVEs that affected the prior pinned versions:

| Package | Old version | Representative CVEs | Severity |
|---|---|---|---|
| Flask | 0.12.5 | CVE-2018-1000656 (DoS via JSON), CVE-2019-1010083 (signing/cookie handling) | High |
| Werkzeug | 0.16.1 | CVE-2020-28724 (open redirect), CVE-2022-29361 (Content-Length parsing), CVE-2023-25577 (multipart DoS), CVE-2023-46136 (multipart DoS), CVE-2024-34069 (debugger RCE), CVE-2024-49766/49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199 | Critical / High |
| Jinja2 | 2.8 | CVE-2016-10745, CVE-2019-10906, CVE-2019-8341, CVE-2020-28493 (ReDoS), CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | High |
| itsdangerous | 1.1.0 | Stale; incompatible with hardened Flask/Werkzeug session handling | Medium |
| MarkupSafe | 1.1.1 | Stale; relied on by Jinja2 hardening | Low |
| click | 7.1.2 | Stale; transitive risk only | Low |

### 2.2 Updated `requirements.txt` (applied)

```
click==8.3.3
Flask==3.1.3
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
Werkzeug==3.1.8
```

### 2.3 Verification

Running `pip-audit -r requirements.txt` against the upgraded pin file:

```
$ python3 -m pip_audit -r requirements.txt
No known vulnerabilities found
```

All known CVEs in direct dependencies have been resolved.

> **Compatibility note:** Flask 3.x removed the `flask.ext` shim and tightened
> several import paths, but the application source uses only modern, supported
> APIs (`Flask`, `Blueprint`, `request`, `jsonify`, `session`, `redirect`,
> `render_template`, `g`) and is compatible with Flask 3.1.

---

## 3. Hardcoded secrets and credentials

### 3.1 Hardcoded Flask `secret_key`

**File:** `flask_webgoat/__init__.py`
**Line:** 22

```python
app.secret_key = "****************************************"
```

**Impact:** A static, in-repo `secret_key` lets anyone with read access to the
source forge session cookies and bypass any authentication that relies on the
Flask session (`session["user_info"]` is set on login).

**Recommended fix:**

```python
import os
import secrets

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(64)
```

Generate a strong key out-of-band and inject it through the deployment
secret store (Azure Key Vault, GitHub Secrets, AWS Secrets Manager, etc.).
Never commit the value.

### 3.2 Hardcoded administrator credentials

**File:** `flask_webgoat/__init__.py`
**Lines:** 33–35

```python
insert_admin_query = """INSERT INTO user (id, username, password, access_level)
VALUES (1, 'admin', 'maximumentropy', 0)"""
```

**Impact:**
- Password is stored in plaintext (no hashing).
- The credential pair (`admin` / `maximumentropy`) is in source control,
  making it trivially discoverable.

**Recommended fix:**

1. Read the bootstrap admin password from an environment variable on first
   boot (or fail closed if not provided).
2. Store passwords using a salted KDF such as `argon2-cffi` or
   `werkzeug.security.generate_password_hash` (PBKDF2/scrypt).
3. Verify with constant-time comparison (`check_password_hash`).

```python
from werkzeug.security import generate_password_hash
admin_password = os.environ["ADMIN_BOOTSTRAP_PASSWORD"]
hashed = generate_password_hash(admin_password)
conn.execute(
    "INSERT INTO user (id, username, password, access_level) VALUES (1, 'admin', ?, 0)",
    (hashed,),
)
```

### 3.3 Sensitive data exposure via SQL trace callback

**File:** `flask_webgoat/__init__.py`
**Line:** 13

```python
conn.set_trace_callback(print)
```

**Impact:** Every executed SQL statement — including statements that contain
the user's plaintext password during login/registration — is printed to
stdout. In any environment that captures container or process logs (most
deployments do), this leaks credentials to logs and observability backends.

**Recommended fix:** Remove the trace callback in production, or route it to
a structured logger that redacts known sensitive parameters.

### 3.4 CI/CD pipeline secrets — review

**File:** `azure-pipelines.yml`

Referenced secrets are *correctly* sourced from the `shiftleft-token`
variable group rather than committed in plaintext:

- `SHIFTLEFT_ORG_ID`
- `SHIFTLEFT_ACCESS_TOKEN`
- `SHIFTLEFT_API_TOKEN`

**Status:** No leak detected. Recommendations:

- Rotate these tokens periodically and scope them to the minimum permissions
  required.
- Ensure the variable group is restricted to this pipeline only.

### 3.5 GitHub Actions workflow

**File:** `.github/workflows/main.yml`

`FACTORY_API_KEY` and `GITHUB_TOKEN` are referenced via `${{ secrets.* }}`
which is the correct mechanism (no inline credentials). No issue.

---

## 4. Authentication & authorization findings

### 4.1 Plaintext password storage and comparison

**File:** `flask_webgoat/__init__.py`, `flask_webgoat/auth.py`,
`flask_webgoat/users.py`

Passwords are stored and compared as plaintext in SQL. Combined with finding
**§3.3** above, plaintext credentials are persisted to disk *and* echoed to
logs.

**Recommended fix:** As in §3.2 — hash on write, `check_password_hash` on
read, no plaintext anywhere in the data path.

### 4.2 Broken Access Control — wildcard CORS

**File:** `run.py`
**Lines:** 6–8

```python
response.headers['Access-Control-Allow-Origin'] = '*'
```

**Impact:** Sets a permissive CORS policy globally. Any origin can read JSON
responses, which is particularly dangerous because this same application
exposes authenticated endpoints (`/message`, `/create_user`) and a session
cookie.

**Recommended fix:** Either remove the header entirely and rely on
same-origin policy, or whitelist trusted origins explicitly and never combine
`Access-Control-Allow-Origin: *` with credentialed requests.

```python
allowed = {"https://app.example.com"}
origin = request.headers.get("Origin")
if origin in allowed:
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Vary'] = 'Origin'
```

### 4.3 Weak access-level check in `/message`

**File:** `flask_webgoat/actions.py`
**Lines:** 13–17

```python
access_level = user_info[2]
if access_level > 2:
    return jsonify({"error": "access level < 2 is required for this action"})
```

The check uses `>` rather than `>=`, and the error message states
`< 2` while the code actually allows `<= 2`. Logic-vs-message mismatches like
this are a frequent source of privilege-escalation bugs.

**Recommended fix:** Align the comparison with the documented intent and
prefer named role constants.

```python
ALLOWED_LEVELS = {0, 1, 2}
if access_level not in ALLOWED_LEVELS:
    return jsonify({"error": "insufficient privileges"}), 403
```

Also return appropriate HTTP status codes (currently authorization failures
return `200 OK`).

### 4.4 Open Redirect on failed login

**File:** `flask_webgoat/auth.py`
**Lines:** 28–46

```python
if result is None:
    return redirect(url)
```

When login fails, the user is redirected to a fully user-controlled URL,
enabling phishing attacks (`/login_and_redirect?...&url=https://evil.tld`).

**Recommended fix:** Validate the redirect target against an allowlist or
ensure it is a relative path:

```python
from urllib.parse import urlparse
parsed = urlparse(url)
if parsed.netloc and parsed.netloc != request.host:
    abort(400)
return redirect(url)
```

### 4.5 Authorization failures returning HTTP 200

Multiple endpoints (`/message`, `/create_user`) return a `200 OK` JSON
payload with an `error` field on authorization failure. This breaks
monitoring (failed authz looks like a success) and may confuse clients.

**Recommended fix:** Return `401`/`403` and `400`/`402` consistently.

---

## 5. SQL injection findings

### 5.1 SQLi in `/login`

**File:** `flask_webgoat/auth.py`
**Lines:** 18–21

```python
query = (
    "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
    % (username, password)
)
result = query_db(query, [], True)
```

User-controlled `username` / `password` are interpolated into the SQL
statement. A payload such as `admin' --` for the username trivially
authenticates as `admin`.

**Recommended fix:** Use parameterized queries. The very next route in the
same file (`/login_and_redirect`) already demonstrates the safe pattern:

```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

### 5.2 SQLi in `/create_user`

**File:** `flask_webgoat/users.py`
**Lines:** 37–41

```python
query = (
    "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
    % (username, password, int(access_level))
)
```

Same root cause; `int(access_level)` is safely coerced, but `username` and
`password` remain interpolated.

**Recommended fix:**

```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, password, int(access_level)), False, True)
```

### 5.3 Search endpoint (informational)

**File:** `flask_webgoat/ui.py`

The `/search` endpoint correctly uses a parameterized query and is **not**
vulnerable to SQL injection. The error path concatenates the user query into
an error message that is rendered through Jinja, so any XSS exposure is
mitigated by Jinja's auto-escape (see §7).

---

## 6. Remote Code Execution and Insecure Deserialization

### 6.1 Command injection in `/grep_processes`

**File:** `flask_webgoat/actions.py`
**Lines:** 41–50

```python
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True,
    capture_output=True,
)
```

`name` is interpolated into a shell pipeline. An attacker can submit
`name=foo; cat /etc/passwd` to execute arbitrary commands.

**Recommended fix:** Avoid `shell=True` entirely, and pass arguments as a
list. Validate / allowlist `name`. If invoking shell utilities is essential,
use `shlex.quote()` on each variable input and treat `name` as opaque data.

```python
import shlex
name = request.args.get("name", "")
if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
    abort(400)
res = subprocess.run(
    ["pgrep", "-af", name],
    capture_output=True, text=True, timeout=5,
)
```

### 6.2 Insecure deserialization in `/deserialized_descr`

**File:** `flask_webgoat/actions.py`
**Lines:** 53–60

```python
pickled = request.form.get('pickled')
data = base64.urlsafe_b64decode(pickled)
deserialized = pickle.loads(data)
```

`pickle.loads` on untrusted input is a well-known RCE primitive — any client
can submit a pickle stream that triggers arbitrary code execution during
unpickling.

**Recommended fix:** Replace pickle with a strict, schema-driven format
(`json`, `msgpack` with a schema, or `pydantic` models). If pickle is truly
required, sign the payload with `itsdangerous.URLSafeTimedSerializer` and
verify before unpickling — but JSON is strongly preferred.

```python
import json
data = json.loads(base64.urlsafe_b64decode(pickled))
```

### 6.3 Directory traversal in `/message`

**File:** `flask_webgoat/actions.py`
**Lines:** 22–37

```python
filename_param = request.form.get("filename")
...
filename = filename_param + ".txt"
path = Path(user_dir + "/" + filename)
with path.open("w", encoding="utf-8") as open_file:
    open_file.write(text_param)
```

`filename_param` is concatenated into a path without sanitization, so a
payload like `filename=../../etc/cron.d/pwn` writes attacker-controlled
content outside the user directory.

**Recommended fix:** Use `werkzeug.utils.secure_filename` and resolve and
verify the final path stays under the user directory:

```python
from werkzeug.utils import secure_filename

safe_name = secure_filename(filename_param) + ".txt"
target = (user_dir_path / safe_name).resolve()
if user_dir_path.resolve() not in target.parents:
    abort(400)
target.write_text(text_param, encoding="utf-8")
```

---

## 7. Cross-Site Scripting (XSS) review

### 7.1 Template rendering — `flask_webgoat/templates/`

- `search.html` renders `num_results`, `query`, and each `result` using Jinja
  expressions (`{{ ... }}`). Flask's Jinja environment **auto-escapes** HTML
  by default, so reflected XSS via the `query` parameter is mitigated.
- `error.html` likewise uses `{{ message }}` with auto-escape enabled.

**Finding:** No XSS sinks were detected. The templates do not use `|safe`,
`Markup(...)`, or `{% autoescape false %}`.

**Recommendation (defense in depth):** Tighten the CSP header (see §8.1) and
explicitly avoid `Markup`/`|safe` when adding new templates that render
user-controlled data.

### 7.2 Error message reflection — `flask_webgoat/ui.py`

```python
message = "Error while executing query " + query_param + ": " + err
return render_template("error.html", message=message)
```

The concatenation looks like a reflection sink, but Jinja's auto-escape will
HTML-escape `message` during rendering, so this is **not** exploitable as
stored/reflected XSS. (It still leaks raw SQL error text to end users, which
is an information-disclosure concern — wrap exceptions and log details
server-side instead.)

---

## 8. Security misconfiguration

### 8.1 Permissive Content Security Policy

**File:** `run.py`
**Line:** 10

```python
response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"
```

`'unsafe-inline'` defeats the primary XSS-mitigation purpose of CSP and
allows inline `<script>` blocks and event handlers to execute.

**Recommended fix:** Remove `'unsafe-inline'`. If inline scripts are
unavoidable, switch to a per-request nonce:

```python
from secrets import token_urlsafe
nonce = token_urlsafe(16)
g.csp_nonce = nonce
response.headers['Content-Security-Policy'] = (
    f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)
```

Add other hardening headers as well:

```python
response.headers.setdefault('X-Content-Type-Options', 'nosniff')
response.headers.setdefault('Referrer-Policy', 'no-referrer')
response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
response.headers.setdefault('X-Frame-Options', 'DENY')
```

### 8.2 Wildcard CORS (also tracked in §4.2)

`Access-Control-Allow-Origin: *` paired with credential-bearing endpoints is
a misconfiguration as well as a broken-access-control issue.

### 8.3 Database file deletion on startup

**File:** `flask_webgoat/__init__.py`
**Lines:** 25–27

```python
db_path = Path(DB_FILENAME)
if db_path.exists():
    db_path.unlink()
```

Every application boot deletes the SQLite DB. This is acceptable for a
training app, but if forked for any real use, this will silently destroy
user data. Recommend gating behind an explicit env flag
(`FLASK_RESET_DB=1`).

### 8.4 Session cookie hardening (defense in depth)

The application does not configure `SESSION_COOKIE_SECURE`,
`SESSION_COOKIE_HTTPONLY` (default `True`), or `SESSION_COOKIE_SAMESITE`.

**Recommended fix:**

```python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
```

---

## 9. CI / pipeline observations

- `azure-pipelines.yml` uses `windows-latest` to enable LCOW (Linux
  containers on Windows). This image is end-of-support; consider migrating
  the scan job to an `ubuntu-latest` agent which runs Linux containers
  natively and avoids the brittle LCOW configuration.
- Secret tokens are correctly referenced via the `shiftleft-token` variable
  group (no plaintext credentials).
- Recommend pinning the ShiftLeft download URL to a specific version and
  verifying its checksum, rather than fetching `sl-latest-windows-x64.zip`,
  to protect against supply-chain tampering.

---

## 10. Files changed by this audit

| File | Change |
|---|---|
| `requirements.txt` | Upgraded all six packages to the latest patched versions; verified clean with `pip-audit`. |
| `security-report.md` | New — this report. |

No application source code was modified, because the in-code vulnerabilities
are part of the intentional `flask-webgoat` training exercise. Each finding
above includes a concrete remediation snippet that can be applied if/when
this codebase is forked for non-training use.

---

## 11. Re-verification commands

```bash
# 1. Dependency audit
python3 -m pip install pip-audit
python3 -m pip_audit -r requirements.txt
# Expected: "No known vulnerabilities found"

# 2. Static secret scan (defense in depth — optional tooling)
pipx run detect-secrets scan --all-files
pipx run bandit -r flask_webgoat

# 3. Smoke-test the upgraded stack
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
FLASK_APP=run.py flask --help
```

---

*End of report.*
