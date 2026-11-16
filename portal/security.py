"""Cross-cutting security controls.

Every control here is traceable to a threat in docs/THREAT_MODEL.md:

  * password hashing ............ T1110 Brute Force            (ASVS 11.4.2)
  * login throttling / lockout .. T1110 Brute Force            (ASVS 6.3.1, 2.4.1)
  * generic failures ............ T1589 identity harvesting    (ASVS 6.3.8)
  * server-side sessions + CSRF . session hijack / CSRF        (ASVS 7.2.x, 7.4.1, 3.5.1)
  * authorisation helpers ....... T1078 Valid Accounts / IDOR  (ASVS 8.2.1, 8.2.2, 8.3.1)
  * audit log ................... repudiation                  (ASVS 16.3.1, 16.3.2)
"""
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from functools import wraps

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import abort, current_app, g, redirect, request, url_for

from .db import get_db

log = logging.getLogger("portal.audit")

# ---------------------------------------------------------------- passwords
_ph = PasswordHasher()  # Argon2id, library defaults (memory-hard KDF)
# Verified against when the username does not exist, so that "unknown user"
# and "wrong password" cost the same time (no timing-based enumeration).
_DUMMY_HASH = _ph.hash(secrets.token_hex(16))

MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128
# Small built-in deny list. Production: check against a full breached-password
# set (ASVS 6.2.4 / 6.2.12) -- recorded as a gap in the threat model.
COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "letmein12345", "iloveyou1234",
    "welcome12345", "administrator", "password12345", "qwerty123456", "university123",
    "studentportal", "changeme1234", "1q2w3e4r5t6y", "abc123456789", "passw0rd1234",
}


def hash_password(password):
    return _ph.hash(password)


def verify_password(pw_hash, password):
    try:
        return _ph.verify(pw_hash or _DUMMY_HASH, password) and pw_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def password_problem(password, username):
    """Return a human-readable problem, or None if the password is acceptable.

    Length-based policy with no composition rules (ASVS 6.2.1, 6.2.5)."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Use at least {MIN_PASSWORD_LEN} characters. A short sentence works well."
    if len(password) > MAX_PASSWORD_LEN:
        return f"Use at most {MAX_PASSWORD_LEN} characters."
    if password.lower() in COMMON_PASSWORDS or username.lower() in password.lower():
        return "That password is too easy to guess. Please choose a different one."
    return None


# -------------------------------------------------------------------- audit
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_for_log(value, limit=80):
    """Strip control characters so user input cannot forge log lines."""
    return _CTRL.sub("?", str(value))[:limit]


def audit(event, detail="", user_id=None):
    """Record a security event. Never pass passwords, OTPs or session tokens."""
    uid = user_id if user_id is not None else (g.user["id"] if g.get("user") else None)
    detail = clean_for_log(detail, 200)
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (ts, user_id, ip, event, detail) VALUES (?, ?, ?, ?, ?)",
        (int(time.time()), uid, request.remote_addr, event, detail),
    )
    db.commit()
    log.info("event=%s user=%s ip=%s detail=%s", event, uid, request.remote_addr, detail)


# ----------------------------------------------------------------- sessions
def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _new_session(user_id=None, state="anon"):
    token = secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG
    now = int(time.time())
    row = {
        "token_hash": _hash_token(token), "user_id": user_id, "state": state,
        "csrf": secrets.token_urlsafe(32), "created_at": now, "last_seen": now,
        "captcha_answer": None, "pending_totp": None, "mfa_failures": 0, "flash": None,
    }
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, state, csrf, created_at, last_seen)"
        " VALUES (:token_hash, :user_id, :state, :csrf, :created_at, :last_seen)", row)
    db.commit()
    g.sess = row
    g.new_cookie = token
    return row


def rotate_session(user_id, state):
    """Issue a brand-new session id whenever the privilege level changes
    (defeats session fixation, ASVS 7.2.4)."""
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.sess["token_hash"],))
    _new_session(user_id, state)
    g.user = None
    if state == "full":
        g.user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def sess_update(**cols):
    sets = ", ".join(f"{k} = ?" for k in cols)  # keys are literals from our own code
    db = get_db()
    db.execute(f"UPDATE sessions SET {sets} WHERE token_hash = ?",
               (*cols.values(), g.sess["token_hash"]))
    db.commit()
    g.sess.update(cols)


def destroy_session():
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.sess["token_hash"],))
    db.commit()
    _new_session()
    g.user = None


def destroy_other_sessions(user_id):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
               (user_id, g.sess["token_hash"]))
    db.commit()


def flash(message, kind="info"):
    items = json.loads(g.sess["flash"] or "[]")
    items.append([kind, message])
    sess_update(flash=json.dumps(items))


def pop_flashes():
    if not g.get("sess") or not g.sess["flash"]:
        return []
    items = json.loads(g.sess["flash"])
    sess_update(flash=None)
    return items


def load_session():
    """before_request hook: resolve the cookie to a server-side session,
    enforce timeouts and verify the CSRF token on every state-changing request."""
    g.user = None
    g.sess = None
    g.new_cookie = None
    if request.endpoint == "static":
        return None
    cfg = current_app.config
    db = get_db()
    now = int(time.time())
    row = None
    token = request.cookies.get(cfg["COOKIE_NAME"])
    if token:
        row = db.execute("SELECT * FROM sessions WHERE token_hash = ?",
                         (_hash_token(token),)).fetchone()
        if row and (now - row["last_seen"] > cfg["IDLE_TIMEOUT"]
                    or now - row["created_at"] > cfg["ABSOLUTE_TIMEOUT"]):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
            db.commit()
            g.timed_out = row["user_id"] is not None
            row = None
    if row is None:
        _new_session()
    else:
        g.sess = dict(row)
        db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                   (now, row["token_hash"]))
        db.commit()
        if row["state"] == "full":
            g.user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()

    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if g.new_cookie or not hmac.compare_digest(sent, g.sess["csrf"]):
            if g.user is None and not g.get("timed_out"):
                # Stale login form: recover gracefully instead of a dead end.
                flash("That page had expired. Please try again.", "warn")
                return redirect(url_for("auth.login"))
            if g.get("timed_out"):
                flash("You were signed out after a period of inactivity. Nothing was saved.", "warn")
                return redirect(url_for("auth.login"))
            audit("csrf_rejected", request.path)
            abort(400)
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            state = g.sess["state"]
            if state == "mfa_pending":
                return redirect(url_for("auth.mfa"))
            if state == "enrol":
                return redirect(url_for("auth.mfa_enrol"))
            if g.get("timed_out"):
                flash("You were signed out after a period of inactivity.", "warn")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    """Function-level access control, enforced on the server (ASVS 8.2.1)."""
    def deco(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] != role:
                deny(f"role {role} required for {request.path}")
            return view(*args, **kwargs)
        return wrapped
    return deco


def deny(reason):
    """Refuse access. We answer 404 rather than 403 so that an attacker cannot
    use the response to learn which record ids exist; the attempt is logged."""
    audit("authz_denied", reason)
    abort(404)


# ---------------------------------------------------- object-level authz
def lecturer_teaches(lecturer_id, student_id):
    return get_db().execute(
        "SELECT 1 FROM courses c JOIN enrolments e ON e.course_id = c.id"
        " WHERE c.lecturer_id = ? AND e.student_id = ?", (lecturer_id, student_id)
    ).fetchone() is not None


def allowed_contacts(user):
    """Who this user may message: students <-> the lecturers who teach them."""
    db = get_db()
    if user["role"] == "student":
        sql = ("SELECT DISTINCT u.id, u.full_name, c.code FROM users u"
               " JOIN courses c ON c.lecturer_id = u.id"
               " JOIN enrolments e ON e.course_id = c.id WHERE e.student_id = ?"
               " ORDER BY u.full_name")
    else:
        sql = ("SELECT DISTINCT u.id, u.full_name, c.code FROM users u"
               " JOIN enrolments e ON e.student_id = u.id"
               " JOIN courses c ON c.id = e.course_id WHERE c.lecturer_id = ?"
               " ORDER BY u.full_name")
    return db.execute(sql, (user["id"],)).fetchall()


# -------------------------------------------------- brute-force defences
WINDOW = 15 * 60          # seconds
CAPTCHA_AFTER = 3         # failures before a challenge is added
LOCK_AFTER = 5            # failures before the account is paused for WINDOW
IP_BLOCK_AFTER = 30       # failures from one address before it is paused


def username_key(username):
    return username.strip().lower()[:64]


def _failures(column, value):
    """Failed attempts inside the window, counted since the last success."""
    db = get_db()
    since = int(time.time()) - WINDOW
    last_ok = db.execute(
        f"SELECT COALESCE(MAX(ts), 0) FROM login_attempts WHERE {column} = ? AND success = 1",
        (value,)).fetchone()[0] if column == "username_key" else 0
    return db.execute(
        f"SELECT COUNT(*) FROM login_attempts WHERE {column} = ? AND success = 0"
        " AND ts >= ? AND ts >= ?", (value, since, last_ok)).fetchone()[0]


def login_risk(username):
    """Returns (captcha_needed, account_locked, ip_blocked).

    Counters are keyed on the *submitted* username whether or not it exists,
    so the lockout behaviour itself reveals nothing about valid accounts."""
    by_user = _failures("username_key", username_key(username)) if username else 0
    by_ip = _failures("ip", request.remote_addr)
    return (by_user >= CAPTCHA_AFTER or by_ip >= CAPTCHA_AFTER,
            by_user >= LOCK_AFTER, by_ip >= IP_BLOCK_AFTER)


def record_attempt(username, success):
    db = get_db()
    db.execute("INSERT INTO login_attempts (username_key, ip, ts, success) VALUES (?, ?, ?, ?)",
               (username_key(username), request.remote_addr, int(time.time()), int(success)))
    db.commit()


def new_captcha():
    """Simple arithmetic challenge kept server-side in the session.

    This slows naive scripts only; it is a stand-in for a real CAPTCHA
    service. Lockout + MFA are the controls that actually stop guessing."""
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    sess_update(captcha_answer=str(a + b))
    return f"{a} + {b}"


def check_captcha(answer):
    expected = g.sess["captcha_answer"]
    sess_update(captcha_answer=None)  # single use
    return bool(expected) and hmac.compare_digest(expected, (answer or "").strip())


# ---------------------------------------------------------------- TOTP MFA
def verify_totp(user, code):
    """Accept the current 30 s step +/- one for clock drift; each step is
    usable once only (ASVS 6.5.1) so a shoulder-surfed code cannot be replayed."""
    code = (code or "").replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return False
    totp = pyotp.TOTP(user["totp_secret"])
    now_counter = int(time.time()) // 30
    for counter in (now_counter - 1, now_counter, now_counter + 1):
        if counter > user["totp_last_counter"] and hmac.compare_digest(totp.at(counter * 30), code):
            db = get_db()
            db.execute("UPDATE users SET totp_last_counter = ? WHERE id = ?", (counter, user["id"]))
            db.commit()
            return True
    return False
