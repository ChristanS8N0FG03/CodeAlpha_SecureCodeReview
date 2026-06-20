"""
VulnPortal — a deliberately vulnerable mini web app
Built ONLY as a target for a secure-coding review exercise.

CodeAlpha Cyber Security Internship — Task 3 (Secure Coding Review)

!!! DO NOT DEPLOY THIS ANYWHERE PUBLIC OR USE ANY CODE FROM IT IN A REAL APP !!!
Every vulnerability below is intentional and documented in CODE_REVIEW_REPORT.md
"""

import sqlite3
import os

from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# --- VULN-01: Hardcoded secret key committed to source control ---
app.secret_key = "supersecret123"

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnportal.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # --- VULN-02: Passwords stored in plaintext ---
    cur.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                ("admin", "admin123", 1))
    cur.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                ("alice", "password1", 0))
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>VulnPortal</h1>
    <p><a href="/login">Login</a> | <a href="/search">Search users</a> | <a href="/upload">Upload avatar</a></p>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # --- VULN-03: SQL Injection — query built with string formatting ---
        query = f"SELECT id, username, is_admin FROM users WHERE username = '{username}' AND password = '{password}'"
        cur.execute(query)
        user = cur.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["is_admin"] = user[2]
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
def dashboard():
    # --- VULN-04: Broken access control — no check that session exists ---
    username = session.get("username", "Guest")
    is_admin = session.get("is_admin", 0)
    return f"<h1>Welcome, {username}</h1><p>Admin: {is_admin}</p>"


@app.route("/search")
def search():
    term = request.args.get("q", "")

    # --- VULN-05: Reflected XSS — user input echoed back unescaped ---
    results_html = f"<h2>Search results for: {term}</h2>"

    if term:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Parameterized here (this one's actually fine) — contrast with /login
        cur.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{term}%",))
        rows = cur.fetchall()
        conn.close()
        results_html += "<ul>" + "".join(f"<li>{r[0]}</li>" for r in rows) + "</ul>"

    return render_template_string("""
        <form method="GET">
            <input name="q" value="{{ term }}">
            <input type="submit" value="Search">
        </form>
        {{ results | safe }}
    """, term=term, results=results_html)
    # --- VULN-05 (cont.): render_template_string + |safe on user-influenced
    # data is a classic XSS vector ---


UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("avatar")
        if f:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            # --- VULN-06: Unrestricted file upload — no type/extension check,
            # filename used as-is (also a path traversal risk) ---
            save_path = os.path.join(UPLOAD_FOLDER, f.filename)
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
    # --- VULN-07: Debug mode enabled — exposes interactive debugger/RCE if
    # an unhandled exception occurs in production ---
    app.run(debug=True, host="0.0.0.0", port=5000)
