"""
auth.py
-------
Minimal session-based authentication for the NIDS dashboard.

What this provides (genuinely):
  - Passwords are hashed with Werkzeug's PBKDF2 implementation -- never
    stored or logged in plaintext.
  - Sessions are Flask's signed-cookie sessions, signed with a secret key
    persisted to a local .secret_key file on first run (random, not
    hardcoded, and gitignored).
  - Per-username login rate limiting: 5 failed attempts locks that
    username out for 60 seconds, to blunt brute forcing.
  - Per-IP signup rate limiting, so self-service account creation can't
    be scripted into mass account spam.
  - A one-time seeded admin account so the dashboard is reachable on
    first run, with a forced "please change this password" banner until
    it's changed. This is the only account with is_admin=True; every
    self-registered account is a normal (non-admin) user.

What this intentionally does NOT provide, so nobody mistakes this
educational implementation for a production-hardened one: CSRF tokens,
multi-factor auth, HTTPS enforcement, or password-reset flows. See the
README for what a real deployment should add on top.
"""

import time
import re
import sqlite3
import threading
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32
MIN_PASSWORD_LENGTH = 6
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")

MAX_SIGNUPS_PER_IP = 6
SIGNUP_WINDOW_SECONDS = 3600

_failed_attempts = {}  # username -> [timestamps of recent failures]
_attempts_lock = threading.Lock()

_signup_attempts = {}  # ip -> [timestamps of recent signup attempts]
_signup_lock = threading.Lock()


def seed_default_admin(conn):
    """If no users exist yet, create one default *admin* account.
    Returns True the first time this happens (caller should warn loudly)."""
    row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row["c"] == 0:
        create_user(conn, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, is_admin=True)
        return True
    return False


def ensure_admin_flag(conn):
    """Migration safety net for databases created before roles existed:
    if a user named 'admin' is already sitting there without is_admin set
    (from an older version of this app), flag it now. No-op for fresh
    installs (seed_default_admin already sets is_admin=True) and a no-op
    for everyone else."""
    conn.execute(
        "UPDATE users SET is_admin = 1 WHERE username = ? AND is_admin = 0",
        (DEFAULT_ADMIN_USERNAME,),
    )
    conn.commit()


def create_user(conn, username, password, is_admin=False):
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), time.time(), 1 if is_admin else 0),
    )
    conn.commit()


def _signup_rate_limited(ip):
    if not ip:
        return False  # no IP info available -- fail open rather than break signup entirely
    with _signup_lock:
        recent = [t for t in _signup_attempts.get(ip, []) if time.time() - t < SIGNUP_WINDOW_SECONDS]
        _signup_attempts[ip] = recent
        return len(recent) >= MAX_SIGNUPS_PER_IP


def _record_signup_attempt(ip):
    if not ip:
        return
    with _signup_lock:
        _signup_attempts.setdefault(ip, []).append(time.time())


def register_user(conn, username, password, confirm_password=None, ip=None):
    """Self-service account creation for new users. Always creates a
    non-admin account -- only seed_default_admin can grant is_admin.
    Returns (success: bool, message: str). Validates + hashes just like
    every other path into the users table; does not touch create_user,
    verify_login, or change_password."""
    if _signup_rate_limited(ip):
        return False, f"Too many accounts created from this network recently. Try again later."
    _record_signup_attempt(ip)

    username = (username or "").strip()

    if not username or not password:
        return False, "Username and password are required."
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."
    if len(username) < MIN_USERNAME_LENGTH or len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be {MIN_USERNAME_LENGTH}-{MAX_USERNAME_LENGTH} characters."
    if not _USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, dots, dashes, and underscores."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return False, "That username is already taken."

    try:
        create_user(conn, username, password, is_admin=False)
    except sqlite3.IntegrityError:
        return False, "That username is already taken."  # race with a concurrent signup
    return True, "Account created."


def _is_locked_out(username):
    with _attempts_lock:
        recent = [t for t in _failed_attempts.get(username, []) if time.time() - t < LOCKOUT_SECONDS]
        _failed_attempts[username] = recent
        return len(recent) >= MAX_FAILED_ATTEMPTS


def _record_failure(username):
    with _attempts_lock:
        _failed_attempts.setdefault(username, []).append(time.time())


def _clear_failures(username):
    with _attempts_lock:
        _failed_attempts.pop(username, None)


def verify_login(conn, username, password):
    """Returns (success: bool, message: str, is_default_login: bool, is_admin: bool)."""
    if not username or not password:
        return False, "Username and password are required.", False, False
    if _is_locked_out(username):
        return False, f"Too many failed attempts. Try again in under {LOCKOUT_SECONDS} seconds.", False, False

    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        _clear_failures(username)
        is_default = username == DEFAULT_ADMIN_USERNAME and password == DEFAULT_ADMIN_PASSWORD
        is_admin = bool(row["is_admin"])
        return True, "ok", is_default, is_admin

    _record_failure(username)
    return False, "Invalid username or password.", False, False


def change_password(conn, username, old_password, new_password):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], old_password):
        return False, "Current password is incorrect."
    if len(new_password) < 6:
        return False, "New password must be at least 6 characters."
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (generate_password_hash(new_password), username),
    )
    conn.commit()
    return True, "Password updated."


def login_required(view_func):
    """For page routes: redirect to the login page if not authenticated."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login_page", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def api_login_required(view_func):
    """For API routes: return 401 JSON instead of redirecting."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"success": False, "message": "Authentication required."}), 401
        return view_func(*args, **kwargs)
    return wrapped


def api_admin_required(view_func):
    """For API routes that should be off-limits to self-registered users --
    currently just the destructive 'reset all data' action. Stacks on top
    of api_login_required's own check (401 if not logged in at all, 403 if
    logged in but not an admin)."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"success": False, "message": "Authentication required."}), 401
        if not session.get("is_admin"):
            return jsonify({"success": False, "message": "Administrator access required."}), 403
        return view_func(*args, **kwargs)
    return wrapped
