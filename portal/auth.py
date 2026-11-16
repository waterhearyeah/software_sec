"""Login, MFA, logout, password change.

Trust boundary TB1 (Internet -> application) is crossed here by anonymous,
attacker-controlled input, so this module assumes every request is hostile.
"""
import time

import pyotp
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import security as sec
from .db import get_db

bp = Blueprint("auth", __name__)

# One message for every failure cause (unknown user, wrong password, paused
# account) so the response never confirms that a username exists (T1589).
GENERIC_FAIL = ("Incorrect username or password. For your protection, sign-in "
                "pauses for 15 minutes after several failed attempts.")
MAX_MFA_TRIES = 5


def _login_page(username="", error=None, status=200):
    captcha_needed, _, _ = sec.login_risk(username)
    challenge = sec.new_captcha() if captcha_needed else None
    return render_template("login.html", username=username, error=error,
                           challenge=challenge), status


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("views.dashboard"))
    if request.method == "GET":
        return _login_page()

    username = request.form.get("username", "")[:64]
    password = request.form.get("password", "")
    captcha_needed, locked, ip_blocked = sec.login_risk(username)
    if ip_blocked:
        sec.audit("login_ip_throttled", sec.clean_for_log(username))
        abort(429)
    if captcha_needed and not sec.check_captcha(request.form.get("captcha")):
        return _login_page(username, "Please answer the verification question to continue.", 400)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?",
                      (sec.username_key(username),)).fetchone()
    # Always run the password hash, even for unknown or paused accounts,
    # so every failure path takes the same time.
    ok = sec.verify_password(user["pw_hash"] if user else None, password[:sec.MAX_PASSWORD_LEN + 1])
    if locked:
        # Not recorded as a new failure: an attacker must not be able to
        # keep a victim locked out forever by continuing to guess.
        sec.audit("login_while_locked", sec.clean_for_log(username))
        return _login_page(username, GENERIC_FAIL, 401)
    if not ok:
        sec.record_attempt(username, False)
        sec.audit("login_failed", sec.clean_for_log(username))
        return _login_page(username, GENERIC_FAIL, 401)

    sec.record_attempt(username, True)
    sec.audit("login_password_ok", user_id=user["id"])
    # Password alone grants nothing: the session is only "mfa_pending".
    if user["totp_secret"]:
        sec.rotate_session(user["id"], "mfa_pending")
        return redirect(url_for("auth.mfa"))
    sec.rotate_session(user["id"], "enrol")
    return redirect(url_for("auth.mfa_enrol"))


def _pending_user(state):
    if g.sess["state"] != state:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (g.sess["user_id"],)).fetchone()


def _complete_login(user):
    db = get_db()
    previous = (user["last_login_at"], user["last_login_ip"])
    db.execute("UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
               (int(time.time()), request.remote_addr, user["id"]))
    db.execute("DELETE FROM sessions WHERE last_seen < ?", (int(time.time()) - 86400,))
    db.commit()
    sec.rotate_session(user["id"], "full")
    sec.audit("login_success", "mfa=totp")
    if previous[0]:
        when = time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(previous[0]))
        sec.flash(f"Signed in. Your previous sign-in was {when} from {previous[1]}. "
                  "If that wasn't you, change your password now.", "info")
    return redirect(url_for("views.dashboard"))


def _mfa_failed(user):
    tries = g.sess["mfa_failures"] + 1
    sec.sess_update(mfa_failures=tries)
    sec.audit("mfa_failed", user_id=user["id"])
    if tries >= MAX_MFA_TRIES:
        # Too many wrong codes: throw the half-open session away and count
        # it against the account so the code cannot be brute-forced.
        sec.record_attempt(user["username"], False)
        sec.destroy_session()
        sec.flash("Too many incorrect codes. Please sign in again.", "warn")
        return redirect(url_for("auth.login"))
    return None


@bp.route("/login/verify", methods=["GET", "POST"])
def mfa():
    user = _pending_user("mfa_pending")
    if not user:
        return redirect(url_for("auth.login"))
    error = None
    if request.method == "POST":
        if sec.verify_totp(user, request.form.get("code")):
            return _complete_login(user)
        bounced = _mfa_failed(user)
        if bounced:
            return bounced
        error = "That code is not correct or has already been used. Wait for a new code and try again."
    return render_template("mfa.html", error=error), (401 if error else 200)


@bp.route("/login/enrol", methods=["GET", "POST"])
def mfa_enrol():
    """MFA is mandatory for every account (closes the lab's 'MFA not yet
    enforced for all users' gap, ASVS 6.3.3)."""
    user = _pending_user("enrol")
    if not user:
        return redirect(url_for("auth.login"))
    secret = g.sess["pending_totp"]
    if not secret:
        secret = pyotp.random_base32()
        sec.sess_update(pending_totp=secret)
    error = None
    if request.method == "POST":
        candidate = dict(user) | {"totp_secret": secret}
        if sec.verify_totp(candidate, request.form.get("code")):
            db = get_db()
            db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
            db.commit()
            sec.audit("mfa_enrolled", user_id=user["id"])
            return _complete_login(user)
        bounced = _mfa_failed(user)
        if bounced:
            return bounced
        error = "That code is not correct. Check the key was entered exactly and try the next code."
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("mfa_enrol.html", secret=grouped, account=user["username"],
                           error=error), (401 if error else 200)


@bp.route("/logout", methods=["POST"])  # POST + CSRF: a link cannot log you out
def logout():
    if g.user:
        sec.audit("logout")
    sec.destroy_session()  # deleted server-side, so the old cookie is useless
    sec.flash("You have been signed out.", "info")
    resp = redirect(url_for("auth.login"))
    resp.headers["Clear-Site-Data"] = '"cache", "storage"'
    return resp


@bp.route("/session/keepalive", methods=["POST"])
@sec.login_required
def keepalive():
    return "", 204


@bp.route("/account/security", methods=["GET", "POST"])
@sec.login_required
def account_security():
    error = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        if not sec.verify_password(g.user["pw_hash"], current):
            sec.audit("password_change_failed")
            error = "Your current password is not correct."
        elif new != request.form.get("confirm_password", ""):
            error = "The new passwords do not match."
        else:
            error = sec.password_problem(new, g.user["username"])
        if not error:
            db = get_db()
            db.execute("UPDATE users SET pw_hash = ? WHERE id = ?",
                       (sec.hash_password(new), g.user["id"]))
            db.commit()
            sec.destroy_other_sessions(g.user["id"])
            sec.rotate_session(g.user["id"], "full")
            sec.audit("password_changed")
            sec.flash("Password changed. Any other devices have been signed out.", "ok")
            return redirect(url_for("auth.account_security"))
    return render_template("security.html", error=error,
                           min_len=sec.MIN_PASSWORD_LEN), (400 if error else 200)
