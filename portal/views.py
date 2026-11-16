"""Authenticated features: grades, attendance, assignments, messages, profile.

Everything here sits behind trust boundary TB2 (authenticated session).
Two rules are applied throughout to stop IDOR / broken access control (T1078):

  1. "My" data is always selected with g.user["id"] from the server-side
     session -- never with a user id taken from the URL or form.
  2. Any record addressed by id is re-authorised against the current user
     on every request before it is returned or changed.
"""
import os
import re
import time

from flask import (Blueprint, current_app, g, redirect, render_template, request,
                   send_file, url_for)

from . import security as sec
from . import uploads
from .db import get_db

bp = Blueprint("views", __name__)


@bp.route("/")
@sec.login_required
def dashboard():
    db, uid = get_db(), g.user["id"]
    unread = db.execute("SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NULL",
                        (uid,)).fetchone()[0]
    if g.user["role"] == "student":
        todo = db.execute(
            "SELECT a.id, a.title, a.due, c.code FROM assignments a"
            " JOIN courses c ON c.id = a.course_id"
            " JOIN enrolments e ON e.course_id = c.id AND e.student_id = ?"
            " LEFT JOIN submissions s ON s.assignment_id = a.id AND s.student_id = ?"
            " WHERE s.id IS NULL ORDER BY a.due", (uid, uid)).fetchall()
        courses = db.execute(
            "SELECT c.code, c.title, u.full_name AS lecturer FROM courses c"
            " JOIN enrolments e ON e.course_id = c.id JOIN users u ON u.id = c.lecturer_id"
            " WHERE e.student_id = ?", (uid,)).fetchall()
        return render_template("dashboard_student.html", unread=unread, todo=todo, courses=courses)
    courses = db.execute(
        "SELECT c.code, c.title,"
        " (SELECT COUNT(*) FROM enrolments e WHERE e.course_id = c.id) AS students,"
        " (SELECT COUNT(*) FROM submissions s JOIN assignments a ON a.id = s.assignment_id"
        "   WHERE a.course_id = c.id) AS submissions"
        " FROM courses c WHERE c.lecturer_id = ?", (uid,)).fetchall()
    return render_template("dashboard_lecturer.html", unread=unread, courses=courses)


# ------------------------------------------------------- grades & attendance
@bp.route("/grades")
@sec.role_required("student")
def grades():
    db, uid = get_db(), g.user["id"]
    rows = db.execute(
        "SELECT c.code, c.title, gr.item, gr.score, gr.max_score FROM grades gr"
        " JOIN courses c ON c.id = gr.course_id WHERE gr.student_id = ? ORDER BY c.code, gr.id",
        (uid,)).fetchall()
    att = db.execute(
        "SELECT c.code, a.day, a.status FROM attendance a JOIN courses c ON c.id = a.course_id"
        " WHERE a.student_id = ? ORDER BY c.code, a.day", (uid,)).fetchall()
    courses = {}
    for r in rows:
        c = courses.setdefault(r["code"], {"title": r["title"], "grades": [], "att": []})
        c["grades"].append(r)
    for a in att:
        courses.setdefault(a["code"], {"title": "", "grades": [], "att": []})["att"].append(a)
    for c in courses.values():
        attended = sum(1 for a in c["att"] if a["status"] != "absent")
        c["att_pct"] = round(100 * attended / len(c["att"])) if c["att"] else None
    return render_template("grades.html", courses=courses)


# --------------------------------------------------------------- assignments
@bp.route("/assignments")
@sec.role_required("student")
def assignments():
    rows = get_db().execute(
        "SELECT a.id, a.title, a.due, c.code, s.id AS sub_id, s.display_name, s.uploaded_at, s.size"
        " FROM assignments a JOIN courses c ON c.id = a.course_id"
        " JOIN enrolments e ON e.course_id = c.id AND e.student_id = ?"
        " LEFT JOIN submissions s ON s.assignment_id = a.id AND s.student_id = ?"
        " ORDER BY a.due, c.code", (g.user["id"], g.user["id"])).fetchall()
    return render_template("assignments.html", rows=rows, max_mb=uploads.MAX_BYTES // 2**20)


@bp.route("/assignments/<int:assignment_id>/submit", methods=["POST"])
@sec.role_required("student")
def submit(assignment_id):
    db, uid = get_db(), g.user["id"]
    # Object-level check: the student must be enrolled in the assignment's course.
    assignment = db.execute(
        "SELECT a.id, a.title FROM assignments a JOIN enrolments e ON e.course_id = a.course_id"
        " WHERE a.id = ? AND e.student_id = ?", (assignment_id, uid)).fetchone()
    if not assignment:
        sec.deny(f"submit to assignment {assignment_id}")
    file = request.files.get("file")
    if not file or not file.filename:
        sec.flash("Choose a file before submitting.", "error")
        return redirect(url_for("views.assignments"))
    data = file.read(uploads.MAX_BYTES + 1)
    upload_dir = current_app.config["UPLOAD_DIR"]
    stored = None
    try:
        ext = uploads.validate(file.filename, data)
        stored, digest = uploads.store(upload_dir, data)
        scan = uploads.malware_scan(os.path.join(upload_dir, stored))
    except uploads.UploadRejected as exc:
        if stored:
            os.remove(os.path.join(upload_dir, stored))
        sec.audit("upload_rejected", f"assignment={assignment_id} reason={exc}")
        sec.flash(f"Not submitted: {exc}", "error")
        return redirect(url_for("views.assignments"))

    old = db.execute("SELECT stored_name FROM submissions WHERE assignment_id = ? AND student_id = ?",
                     (assignment_id, uid)).fetchone()
    db.execute(
        "INSERT INTO submissions (assignment_id, student_id, stored_name, display_name, ext, size,"
        " sha256, scan_status, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (assignment_id, student_id) DO UPDATE SET stored_name = excluded.stored_name,"
        " display_name = excluded.display_name, ext = excluded.ext, size = excluded.size,"
        " sha256 = excluded.sha256, scan_status = excluded.scan_status,"
        " uploaded_at = excluded.uploaded_at",
        (assignment_id, uid, stored, uploads.display_name(file.filename), ext, len(data),
         digest, scan, int(time.time())))
    db.commit()
    if old:  # one file per assignment keeps each student's storage bounded
        try:
            os.remove(os.path.join(upload_dir, old["stored_name"]))
        except FileNotFoundError:
            pass
    sec.audit("upload_accepted", f"assignment={assignment_id} sha256={digest[:16]} scan={scan}")
    sec.flash(f"Submitted “{assignment['title']}”. Receipt (SHA-256): {digest[:16]}…", "ok")
    return redirect(url_for("views.assignments"))


@bp.route("/submissions")
@sec.role_required("lecturer")
def submissions():
    rows = get_db().execute(
        "SELECT s.id, s.display_name, s.size, s.uploaded_at, s.scan_status, s.sha256,"
        " a.title, a.due, c.code, u.full_name, u.id AS student_id"
        " FROM submissions s JOIN assignments a ON a.id = s.assignment_id"
        " JOIN courses c ON c.id = a.course_id JOIN users u ON u.id = s.student_id"
        " WHERE c.lecturer_id = ? ORDER BY s.uploaded_at DESC", (g.user["id"],)).fetchall()
    return render_template("submissions.html", rows=rows)


@bp.route("/submissions/<int:submission_id>/download")
@sec.login_required
def download(submission_id):
    row = get_db().execute(
        "SELECT s.*, c.lecturer_id, u.username FROM submissions s"
        " JOIN assignments a ON a.id = s.assignment_id JOIN courses c ON c.id = a.course_id"
        " JOIN users u ON u.id = s.student_id WHERE s.id = ?", (submission_id,)).fetchone()
    # Only the student who uploaded it or the lecturer of that course.
    if not row or g.user["id"] not in (row["student_id"], row["lecturer_id"]):
        sec.deny(f"download submission {submission_id}")
    sec.audit("submission_downloaded", f"submission={submission_id}")
    # The download name is generated by the server, not taken from the upload.
    name = f"{row['username']}_assignment{row['assignment_id']}.{row['ext']}"
    resp = send_file(os.path.join(current_app.config["UPLOAD_DIR"], row["stored_name"]),
                     mimetype=uploads.MIME[row["ext"]], as_attachment=True, download_name=name)
    # Force "save", never render inside the portal's origin.
    resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return resp


# ------------------------------------------------------------------ messages
SUBJECT_MAX, BODY_MAX, MESSAGES_PER_HOUR = 120, 4000, 30


@bp.route("/messages")
@sec.login_required
def messages():
    db, uid = get_db(), g.user["id"]
    inbox = db.execute(
        "SELECT m.id, m.subject, m.sent_at, m.read_at, u.full_name AS other FROM messages m"
        " JOIN users u ON u.id = m.sender_id WHERE m.recipient_id = ? ORDER BY m.sent_at DESC",
        (uid,)).fetchall()
    sent = db.execute(
        "SELECT m.id, m.subject, m.sent_at, m.read_at, u.full_name AS other FROM messages m"
        " JOIN users u ON u.id = m.recipient_id WHERE m.sender_id = ? ORDER BY m.sent_at DESC",
        (uid,)).fetchall()
    return render_template("messages.html", inbox=inbox, sent=sent)


@bp.route("/messages/<int:message_id>")
@sec.login_required
def message(message_id):
    db, uid = get_db(), g.user["id"]
    m = db.execute(
        "SELECT m.*, s.full_name AS sender, r.full_name AS recipient FROM messages m"
        " JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.recipient_id"
        " WHERE m.id = ?", (message_id,)).fetchone()
    if not m or uid not in (m["sender_id"], m["recipient_id"]):
        sec.deny(f"read message {message_id}")
    if m["recipient_id"] == uid and not m["read_at"]:
        db.execute("UPDATE messages SET read_at = ? WHERE id = ?", (int(time.time()), message_id))
        db.commit()
    return render_template("message.html", m=m, mine=m["sender_id"] == uid)


@bp.route("/messages/new", methods=["GET", "POST"])
@sec.login_required
def message_new():
    db, uid = get_db(), g.user["id"]
    contacts = sec.allowed_contacts(g.user)
    allowed_ids = {c["id"] for c in contacts}
    form = {"to": request.values.get("to", ""), "subject": request.form.get("subject", ""),
            "body": request.form.get("body", "")}
    reply = request.args.get("reply", "")
    if reply.isdigit():
        # Only an id travels in the URL (no message text); the original is
        # looked up and re-authorised here.
        original = db.execute("SELECT sender_id, subject FROM messages WHERE id = ? AND recipient_id = ?",
                              (int(reply), uid)).fetchone()
        if not original:
            sec.deny(f"reply to message {reply}")
        subject = original["subject"]
        form["to"] = str(original["sender_id"])
        form["subject"] = subject if subject.lower().startswith("re:") else "Re: " + subject
    error = None
    if request.method == "POST":
        subject, body = form["subject"].strip(), form["body"].strip()
        recent = db.execute("SELECT COUNT(*) FROM messages WHERE sender_id = ? AND sent_at > ?",
                            (uid, int(time.time()) - 3600)).fetchone()[0]
        if not form["to"].isdigit() or int(form["to"]) not in allowed_ids:
            # The recipient list in the page is only a convenience; the rule
            # is enforced here because the form can be tampered with.
            sec.audit("message_recipient_rejected", form["to"])
            error = "Choose a recipient from the list."
        elif not subject or len(subject) > SUBJECT_MAX:
            error = f"Enter a subject of up to {SUBJECT_MAX} characters."
        elif not body or len(body) > BODY_MAX:
            error = f"Enter a message of up to {BODY_MAX} characters."
        elif recent >= MESSAGES_PER_HOUR:
            sec.audit("message_rate_limited")
            error = "You have sent a lot of messages in the last hour. Please try again later."
        else:
            db.execute("INSERT INTO messages (sender_id, recipient_id, subject, body, sent_at)"
                       " VALUES (?, ?, ?, ?, ?)", (uid, int(form["to"]), subject, body, int(time.time())))
            db.commit()
            sec.audit("message_sent", f"to={form['to']}")
            sec.flash("Message sent.", "ok")
            return redirect(url_for("views.messages"))
    return render_template("message_new.html", contacts=contacts, form=form, error=error,
                           subject_max=SUBJECT_MAX, body_max=BODY_MAX), (400 if error else 200)


# ------------------------------------------------------------------- profile
# Allow-list of editable fields with a validation rule each (ASVS 2.2.1).
# Anything else in the form (role, username, id...) is ignored, which
# prevents mass-assignment / privilege escalation (ASVS 8.2.3).
PROFILE_RULES = {
    "email": (re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,20}"),
              "Enter a valid email address, like name@example.edu."),
    "phone": (re.compile(r"\+?[0-9][0-9 ()-]{6,19}"),
              "Enter a phone number using digits, spaces, + and - only."),
    "address": (re.compile(r"[^<>\x00-\x08\x0b-\x1f]{0,200}", re.S),
                "Address can be up to 200 characters and cannot contain < or >."),
    "emergency_contact": (re.compile(r"[^<>\x00-\x1f]{0,120}"),
                          "Emergency contact can be up to 120 characters and cannot contain < or >."),
}


@bp.route("/profile", methods=["GET", "POST"])
@sec.login_required
def profile():
    values = {f: g.user[f] for f in PROFILE_RULES}
    errors = {}
    if request.method == "POST":
        for field, (rule, message) in PROFILE_RULES.items():
            values[field] = request.form.get(field, "").strip()
            if not rule.fullmatch(values[field]):
                errors[field] = message
        email_changed = values["email"].lower() != g.user["email"].lower()
        # Email is the account-recovery channel, so changing it needs the
        # password again -- a hijacked session alone is not enough (ASVS 7.5.1).
        if email_changed and not errors and not sec.verify_password(
                g.user["pw_hash"], request.form.get("current_password", "")):
            sec.audit("profile_reauth_failed")
            errors["current_password"] = "Enter your current password to change your email address."
        if not errors:
            db = get_db()
            db.execute("UPDATE users SET email = ?, phone = ?, address = ?, emergency_contact = ?"
                       " WHERE id = ?",  # id comes from the session, not the request
                       (values["email"], values["phone"], values["address"],
                        values["emergency_contact"], g.user["id"]))
            db.commit()
            changed = [f for f in PROFILE_RULES if values[f] != g.user[f]]
            sec.audit("profile_updated", "fields=" + ",".join(changed))  # names only, no values
            sec.flash("Your contact details have been saved.", "ok")
            return redirect(url_for("views.profile"))
    return render_template("profile.html", values=values, errors=errors), (400 if errors else 200)


@bp.route("/students")
@sec.role_required("lecturer")
def roster():
    rows = get_db().execute(
        "SELECT u.id, u.full_name, u.username, c.code FROM users u"
        " JOIN enrolments e ON e.student_id = u.id JOIN courses c ON c.id = e.course_id"
        " WHERE c.lecturer_id = ? ORDER BY c.code, u.full_name", (g.user["id"],)).fetchall()
    return render_template("roster.html", rows=rows)


@bp.route("/students/<int:student_id>")
@sec.role_required("lecturer")
def student(student_id):
    # Contact details are visible only to a lecturer who teaches this student.
    if not sec.lecturer_teaches(g.user["id"], student_id):
        sec.deny(f"view student {student_id}")
    s = get_db().execute(
        "SELECT id, full_name, username, email, phone, emergency_contact FROM users"
        " WHERE id = ? AND role = 'student'", (student_id,)).fetchone()
    sec.audit("student_contact_viewed", f"student={student_id}")
    return render_template("student.html", s=s)
