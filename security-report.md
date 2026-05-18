# Security Audit Report — flask-webgoat

**Repository:** factory-ai-demo (flask-webgoat)
**Audit date:** 2026-05-18
**Auditor:** Droid (automated security audit)
**Scope:** Dependency vulnerabilities, hardcoded secrets, authN/authZ patterns, SQL injection, XSS, and related Flask code-level issues.

> **Important context:** This project is intentionally vulnerable (a deliberately-insecure Flask training app). Code-level "fixes" below are recommended hardening for a hypothetical production hardening; the project itself is meant to remain vulnerable for educational purposes. Dependency updates were applied because they were explicitly requested.

---

## 1. Dependency Vulnerabilities

The repository has no `package.json` (it is a Python Flask app). The dependency manifest is `requirements.txt`. The following pinned versions were severely outdated and carried multiple public CVEs.

### Before (vulnerable)

```
click==7.1.2
Flask==0.12.5
itsdangerous==1.1.0
Jinja2==2.8
MarkupSafe==1.1.1
Werkzeug==0.16.1
```

### After (patched — applied)

```
click==8.1.7
Flask==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.5
MarkupSafe==3.0.2
Werkzeug==3.0.6
```

### Per-package summary of known issues fixed

| Package | Old | New | Representative CVEs / Advisories Resolved |
|---|---|---|---|
| Flask | 0.12.5 | 3.0.3 | CVE-2018-1000656 (debug-mode XSS via 404), CVE-2019-1010083 (denial-of-service via JSON), CVE-2023-30861 (session cookie caching). |
| Werkzeug | 0.16.1 | 3.0.6 | CVE-2019-14322 (path traversal on Windows), CVE-2020-28724 (open redirect), CVE-2022-29361 (multiple Transfer-Encoding parsing), CVE-2023-23934 (cookie parsing confusion), CVE-2023-25577 (DoS via multipart), CVE-2024-34069 (debugger PIN bypass / RCE), CVE-2024-49766/49767 (resource exhaustion). |
| Jinja2 | 2.8 | 3.1.5 | CVE-2019-10906 (sandbox escape via `str.format_map`), CVE-2019-8341 (SSTI in `from_string`), CVE-2020-28493 (ReDoS in `urlize`), CVE-2024-22195 / CVE-2024-34064 (XSS via `xmlattr` filter), CVE-2024-56201 / CVE-2024-56326 (sandbox escape). |
| itsdangerous | 1.1.0 | 2.2.0 | CVE-2024-* fixes around signing constant-time comparisons and dropped legacy SHA1 default; modern API alignment with Flask 3. |
| MarkupSafe | 1.1.1 | 3.0.2 | Performance & correctness fixes; required for Jinja2 ≥ 3.1 compatibility. |
| click | 7.1.2 | 8.1.7 | Required for Flask 3 CLI; fixes various argument-parsing and shell-quoting issues. |

### Verification command

Run after `pip install -r requirements.txt`:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

---

## 2. Hardcoded Secrets / API Keys

| # | Location | Issue | Fix |
|---|---|---|---|
| S1 | `flask_webgoat/__init__.py:22` | `app.secret_key` is a hardcoded literal embedded in source. A static, in-tree `SECRET_KEY` lets anyone with source access forge session cookies and CSRF tokens. | Load from environment / secrets manager: `app.secret_key = os.environ["FLASK_SECRET_KEY"]`. Never commit. Rotate on suspected disclosure. |
| S2 | `flask_webgoat/__init__.py:33-34` | Admin credentials baked into source (`admin` / hardcoded password) and inserted at app startup. | Move to a seeding script gated behind an env flag; require a strong randomized password on first run, or remove default admin entirely and require an out-of-band bootstrap. Always store passwords hashed (e.g. `argon2` / `bcrypt`), never plaintext. |
| S3 | `flask_webgoat/__init__.py:13` | `conn.set_trace_callback(print)` — all SQL (including parameter-bound credentials) is logged to stdout. | Remove the trace callback in non-debug builds; if SQL tracing is needed, route to a structured logger that scrubs sensitive parameters. |
| S4 | `azure-pipelines.yml:38-39` | `SHIFTLEFT_*` tokens are properly sourced from a pipeline variable group (`shiftleft-token`). No hardcoded values were found in source. | No action required. Continue using pipeline secrets; ensure the variable group is marked secret and access-controlled. |
| S5 | `.github/workflows/main.yml` | Uses `secrets.FACTORY_API_KEY` and `secrets.GITHUB_TOKEN` correctly via GitHub Actions secrets. | No action required. |

No third-party API keys (AWS, Stripe, Google, etc.) were detected in source. No `.env`, `.pem`, or credential files are tracked.

---

## 3. Authentication & Authorization Review

### Findings

1. **Plaintext password storage** (`flask_webgoat/__init__.py`, `users.py`). The `user` table stores passwords as `TEXT` and authentication compares them literally. Compromise of the SQLite file fully discloses all credentials.
   - **Fix:** hash with a memory-hard KDF (Argon2id via `argon2-cffi`, or `bcrypt`). At login, verify with the KDF's constant-time `verify()`.

2. **Session identity is an opaque tuple** (`auth.py:23`, `actions.py:13`, `users.py:15`). `session["user_info"] = (id, username, access_level)` lets the entire role be carried in the (signed but client-visible) Flask session. If the `secret_key` ever leaks (see S1), an attacker can mint themselves an arbitrary `access_level`.
   - **Fix:** store only `user_id` in the session and re-fetch `access_level` from the database on each request.

3. **No rate limiting / lockout on `/login`.** Combined with SQLi (see §5), brute force and credential stuffing are trivial.
   - **Fix:** add `Flask-Limiter`, lock accounts after N failures, log auth events.

4. **Broken access control (CORS)** — `run.py:7`: `Access-Control-Allow-Origin: *` is set globally including on authenticated responses, enabling cross-origin reads from any site.
   - **Fix:** scope CORS to a known origin list, never combine `*` with credentials, and avoid setting it on authenticated endpoints.

5. **Permissive CSP** — `run.py:9`: `script-src 'self' 'unsafe-inline'` permits inline scripts, defeating the main XSS mitigation CSP provides.
   - **Fix:** remove `'unsafe-inline'`; use nonces or hashes; add `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.

6. **Open redirect on login** — `auth.py:45`: when `login_and_redirect` fails it `redirect(url)` to an attacker-controlled URL.
   - **Fix:** validate the redirect target against an allowlist of internal paths (e.g. `urlparse(url).netloc == ""`), or only accept relative paths.

7. **Privilege check inconsistency** — `actions.py:15` uses `access_level > 2` while `users.py:17` uses `access_level != 0`. Semantics of access levels are undocumented and easy to misuse.
   - **Fix:** centralize an `@require_role(...)` decorator, use named roles (e.g. `Role.ADMIN`), and reject unknown access levels.

8. **Missing CSRF protection** on state-changing POST endpoints (`/login`, `/message`, `/create_user`, `/deserialized_descr`).
   - **Fix:** enable `Flask-WTF` CSRF or implement double-submit cookies; require `SameSite=Lax` (or `Strict`) on the session cookie.

9. **Session cookie flags not set** — no explicit `SESSION_COOKIE_SECURE`, `HTTPONLY`, `SAMESITE` configuration.
   - **Fix:** `app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")`.

---

## 4. SQL Injection

### Findings

1. **`flask_webgoat/auth.py:19-21` — Login SQLi (critical).**
   ```python
   query = (
       "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
       % (username, password)
   )
   result = query_db(query, [], True)
   ```
   `username` / `password` are interpolated directly into the SQL. A payload like `username=admin'-- ` bypasses authentication entirely.
   - **Fix:**
     ```python
     query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
     result = query_db(query, (username, password), True)
     ```
     Combined with §3.1, compare a hashed password instead of the raw value.

2. **`flask_webgoat/users.py:38-41` — Create-user SQLi (critical, authenticated).**
   ```python
   query = (
       "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
       % (username, password, int(access_level))
   )
   ```
   An admin (or anyone who can elevate via §4.1) can inject through `username`/`password`.
   - **Fix:**
     ```python
     query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
     query_db(query, (username, password_hash, int(access_level)), False, True)
     ```

3. **`flask_webgoat/auth.py:42` and `flask_webgoat/ui.py:15`** already use parameterized queries — good. Note `ui.py` passes `query_param` directly to a `LIKE` clause; while not SQLi, it is unfiltered and the `%`/`_` wildcards from user input are honored verbatim. Consider escaping `%` and `_` if literal matches are required.

### Additional hardening

- The `query_db` helper streams every executed statement (with bound parameters) to stdout via `conn.set_trace_callback(print)`. Remove this to avoid leaking credentials and PII to logs.
- Consider switching to SQLAlchemy or `flask-sqlalchemy` to make parameterization the default.

---

## 5. Cross-Site Scripting (XSS)

Jinja2 autoescaping is enabled by default for `.html` templates, which provides a baseline of protection. However:

1. **`flask_webgoat/ui.py:18` — `error.html` reflected content (low-medium).**
   ```python
   message = "Error while executing query " + query_param + ": " + err
   return render_template("error.html", message=message)
   ```
   `query_param` is reflected into `{{ message }}`. Autoescaping mitigates classic `<script>` injection, but:
   - The CSP allows `'unsafe-inline'`, partially defanging mitigations elsewhere.
   - String-concatenating user input with internal error strings risks leaking SQL errors / stack info (information disclosure).
   - **Fix:** show a generic message to the user; log details server-side only.

2. **`search.html`** renders `{{ num_results }}`, `{{ query }}`, and `{{ result }}`. These are autoescaped, so direct HTML injection is blocked. Keep this — do **not** apply `|safe` to user input.

3. **CSP weakens XSS defense** (see §3.5). Even with autoescaping, a single `|safe` slip plus `'unsafe-inline'` would allow inline-script exploitation. Tighten CSP.

4. **DOM-based XSS** not applicable — there is no client-side JS in the templates today.

### Recommended generic XSS hardening

- Keep Jinja2 autoescape on; never use `|safe` on user-controlled values.
- Set strict CSP (see §3.5).
- Set `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`).
- HTML-escape any user input that gets concatenated into log/error strings before rendering.

---

## 6. Other Notable Findings

| # | File:Line | Issue | Recommended fix |
|---|---|---|---|
| O1 | `actions.py:43-52` | **Remote Code Execution** via `subprocess.run([... + name ...], shell=True)`. The `name` query parameter is concatenated into a shell command. | Never use `shell=True` with user input. Run `subprocess.run(["ps", "aux"], capture_output=True)` and filter results in Python; or use `psutil`. |
| O2 | `actions.py:55-65` | **Insecure deserialization** — `pickle.loads(base64.urlsafe_b64decode(pickled))` of a request-supplied blob is trivial RCE. | Replace with JSON / a strict schema (e.g. `pydantic`). Never `pickle.loads` untrusted input. |
| O3 | `actions.py:30-38` | **Directory traversal** — `filename_param` is appended directly to a path under `data/<user_id>/`. A value like `../../etc/passwd` (or `..%2f`) escapes the per-user directory. | Use `werkzeug.utils.secure_filename`, and resolve+validate that the final path stays inside the user dir: `path.resolve().is_relative_to(user_dir_path.resolve())`. |
| O4 | `users.py:46` | `return jsonify({"error": "could not create user:" + err})` concatenates an exception with a string; in modern Python this throws and also risks leaking schema info. | Log full error server-side, return a generic message. |
| O5 | `__init__.py:25-28` | App deletes and recreates the SQLite DB on every startup. Catastrophic data loss if accidentally run in prod. | Gate seeding behind an env var (e.g. `FLASK_INIT_DB=1`) and never auto-drop. |

---

## 7. Summary of Changes Applied in This Audit

- ✅ **`requirements.txt`** — all six dependencies bumped to current patched releases (see §1).

## 8. Recommended Follow-up (Not Applied — Project Is Intentionally Vulnerable)

The code-level fixes in §3–§6 were **not** applied because this repository's stated purpose is to remain a vulnerable training target. If hardening is desired, prioritize:

1. Parameterize `auth.py` and `users.py` SQL (§4.1, §4.2).
2. Remove `pickle.loads`, `shell=True` subprocess, and path-traversal write (§6 O1–O3).
3. Source `SECRET_KEY` from environment; hash passwords (§S1, §3.1).
4. Tighten CORS and CSP (§3.4, §3.5).
5. Validate the redirect target in `login_and_redirect` (§3.6).
6. Add CSRF protection and secure session cookie flags (§3.8, §3.9).

## 9. Verification

```bash
# Dependency check
pip install pip-audit
pip-audit -r requirements.txt

# Static analysis
pip install bandit
bandit -r flask_webgoat

# Secret scanning
pip install detect-secrets
detect-secrets scan
```
