"""
VulnPortal — FIXED version
Same features as app.py, with all 7 findings from CODE_REVIEW_REPORT.md remediated.

CodeAlpha Cyber Security Internship — Task 3 (Secure Coding Review)
"""

import sqlite3
import os

from flask import Flask, request, render_template_string, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)

# FIX for VULN-01: secret key loaded from environment, not hardcoded.
# Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnportal_fixed.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # FIX for VULN-02: passwords are hashed before storage, never stored raw.
    cur.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        ("admin", generate_password_hash("admin123"), 1),
    )
    cur.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        ("alice", generate_password_hash("password1"), 0),
    )
    conn.commit()
    conn.close()


# FIX for VULN-04: reusable decorator instead of ad-hoc per-route checks
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    return """
    <h1>VulnPortal (Fixed)</h1>
    <p><a href="/login">Login</a> | <a href="/search">Search users</a> | <a href="/upload">Upload avatar</a></p>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # FIX for VULN-03: parameterized query — no string formatting of user input
        cur.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()
        conn.close()

        # FIX for VULN-02: compare against hash, not plaintext
        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["is_admin"] = user[3]
            return redirect("/dashboard")
        else:
            return "Invalid credentials", 401

    return """
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    """


@app.route("/dashboard")
@login_required
def dashboard():
    # FIX for VULN-04: route is now gated by @login_required above
    username = session.get("username")
    is_admin = session.get("is_admin", 0)
    return render_template_string(
        "<h1>Welcome, {{ username }}</h1><p>Admin: {{ is_admin }}</p>",
        username=username, is_admin=is_admin,
    )


@app.route("/search")
def search():
    term = request.args.get("q", "")
    rows = []

    if term:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{term}%",))
        rows = cur.fetchall()
        conn.close()

    # FIX for VULN-05: no |safe, no manual HTML building — Jinja2 auto-escapes
    # both the echoed search term and each result.
    return render_template_string("""
        <form method="GET">
            <input name="q" value="{{ term }}">
            <input type="submit" value="Search">
        </form>
        <h2>Search results for: {{ term }}</h2>
        <ul>
        {% for username in usernames %}
            <li>{{ username }}</li>
        {% endfor %}
        </ul>
    """, term=term, usernames=[r[0] for r in rows])


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("avatar")
        if not f or f.filename == "":
            return "No file selected", 400

        # FIX for VULN-06: extension allowlist + secure_filename to prevent
        # path traversal and arbitrary file type upload
        if not allowed_file(f.filename):
            return "Invalid file type. Allowed: png, jpg, jpeg, gif", 400

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filename = secure_filename(f.filename)
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        f.save(save_path)
        return f"Uploaded to {save_path}"

    return """
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="avatar">
            <input type="submit" value="Upload">
        </form>
    """


if __name__ == "__main__":
    init_db()
    # FIX for VULN-07: debug mode controlled by environment, defaults to off
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
