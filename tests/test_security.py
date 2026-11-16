"""Security regression tests -- each one verifies a control from the threat
model (the "Verifiable" column of Lab 1 Part 4).  Run:  pytest -q
"""
import io
import re
import time
import zipfile

import pyotp
import pytest

from portal import create_app, db, security

PASSWORD = "correct horse battery"


@pytest.fixture()
def app(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path), "HTTPS_ONLY": True, "TESTING": True})
    hashed = security.hash_password(PASSWORD)
    with app.app_context():
        db.seed(lambda username: hashed)
        # Pre-enrol MFA so tests can generate codes.
        db.get_db().execute("UPDATE users SET totp_secret = ?", (pyotp.random_base32(),))
        db.get_db().commit()
    return app


def client_for(app):
    return app.test_client()


def csrf(client, path="/login"):
    html = client.get(path, base_url="https://localhost").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(client, path, data=None, **kw):
    data = dict(data or {})
    form_page = kw.pop("form_page", "/login")
    if "csrf_token" not in data:
        data["csrf_token"] = csrf(client, form_page)
    return client.post(path, data=data, base_url="https://localhost", **kw)


def get(client, path):
    return client.get(path, base_url="https://localhost")


def query(app, sql, args=()):
    with app.app_context():
        return db.get_db().execute(sql, args).fetchall()


def totp_now(app, username, offset=0):
    secret = query(app, "SELECT totp_secret FROM users WHERE username = ?", (username,))[0][0]
    return pyotp.TOTP(secret).at(time.time() + offset)


def login(app, username):
    c = client_for(app)
    r = post(c, "/login", {"username": username, "password": PASSWORD})
    assert r.status_code == 302 and r.headers["Location"].endswith("/login/verify")
    r = post(c, "/login/verify", {"code": totp_now(app, username)}, form_page="/login/verify")
    assert r.status_code == 302
    return c


def uid(app, username):
    return query(app, "SELECT id FROM users WHERE username = ?", (username,))[0][0]


def pdf(extra=b""):
    return b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n" + extra + b"%%EOF"


def docx(macro=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        if macro:
            z.writestr("word/vbaProject.bin", b"\x00")
    return buf.getvalue()


def upload(app, client, assignment_id, name, data):
    return post(client, f"/assignments/{assignment_id}/submit",
                {"file": (io.BytesIO(data), name)}, form_page="/assignments",
                content_type="multipart/form-data")


# ---------------------------------------------------------------- transport
def test_plain_http_is_redirected_to_https(app):
    r = client_for(app).get("/login", base_url="http://localhost")
    assert r.status_code == 308 and r.headers["Location"].startswith("https://")


def test_security_headers_and_cookie_flags(app):
    r = get(client_for(app), "/login")
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in r.headers["Strict-Transport-Security"]
    assert r.headers["Cache-Control"] == "no-store"
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("__Host-sid=")
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        assert flag in cookie


# ------------------------------------------- story 1: login (T1110, T1589)
def test_unknown_user_and_wrong_password_are_indistinguishable(app):
    a = post(client_for(app), "/login", {"username": "s1001", "password": "wrong-password-1"})
    b = post(client_for(app), "/login", {"username": "nobody99", "password": "wrong-password-1"})
    assert a.status_code == b.status_code == 401
    strip = lambda r: re.sub(r'value="[^"]*"', "", r.get_data(as_text=True))
    assert strip(a) == strip(b)


def test_captcha_then_lockout_even_with_correct_password(app):
    c = client_for(app)
    for _ in range(3):
        post(c, "/login", {"username": "s1002", "password": "bad"})
    r = post(c, "/login", {"username": "s1002", "password": "bad"})
    assert r.status_code == 400 and "verification question" in r.get_data(as_text=True)

    # Push the account over the lock threshold directly, then try the real password.
    with app.app_context():
        for _ in range(2):
            db.get_db().execute(
                "INSERT INTO login_attempts (username_key, ip, ts, success) VALUES ('s1002', '10.9.9.9', ?, 0)",
                (int(time.time()),))
        db.get_db().commit()
    fresh = client_for(app)
    html = get(fresh, "/login").get_data(as_text=True)
    a, b = map(int, re.search(r"what is <b>(\d+) \+ (\d+)</b>", html).groups())
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = post(fresh, "/login", {"username": "s1002", "password": PASSWORD, "captcha": str(a + b),
                               "csrf_token": token})
    assert r.status_code == 401  # locked: correct password is still refused
    assert query(app, "SELECT COUNT(*) FROM audit_log WHERE event = 'login_while_locked'")[0][0] == 1


def test_password_alone_does_not_grant_access(app):
    c = client_for(app)
    post(c, "/login", {"username": "s1001", "password": PASSWORD})
    r = get(c, "/grades")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login/verify")


def test_totp_code_cannot_be_replayed(app):
    code = totp_now(app, "s1001")
    c = client_for(app)
    post(c, "/login", {"username": "s1001", "password": PASSWORD})
    assert post(c, "/login/verify", {"code": code}, form_page="/login/verify").status_code == 302
    c2 = client_for(app)
    post(c2, "/login", {"username": "s1001", "password": PASSWORD})
    assert post(c2, "/login/verify", {"code": code}, form_page="/login/verify").status_code == 401


def test_session_id_rotates_on_login_and_dies_on_logout(app):
    c = client_for(app)
    get(c, "/login")
    before = c.get_cookie("__Host-sid", domain="localhost").value
    post(c, "/login", {"username": "s1001", "password": PASSWORD})
    post(c, "/login/verify", {"code": totp_now(app, "s1001")}, form_page="/login/verify")
    authed = c.get_cookie("__Host-sid", domain="localhost").value
    assert authed != before
    post(c, "/logout", form_page="/profile")
    stolen = client_for(app)
    stolen.set_cookie("__Host-sid", authed, domain="localhost", secure=True)
    assert get(stolen, "/grades").status_code == 302  # old token is worthless


def test_idle_timeout_enforced_server_side(app):
    c = login(app, "s1001")
    with app.app_context():
        db.get_db().execute("UPDATE sessions SET last_seen = last_seen - 16 * 60")
        db.get_db().commit()
    assert get(c, "/grades").status_code == 302


def test_post_without_csrf_token_is_rejected(app):
    c = login(app, "s1001")
    r = c.post("/profile", data={"email": "evil@example.com", "phone": "+60 12 000 0000"},
               base_url="https://localhost")
    assert r.status_code == 400
    assert query(app, "SELECT email FROM users WHERE username = 's1001'")[0][0].startswith("aisha")


# ---------------------------------------- story 2: upload (T1204.002)
@pytest.mark.parametrize("name,data", [
    ("report.exe", b"MZ\x90\x00"),
    ("report.pdf.exe", pdf()),
    ("report.pdf", b"MZ\x90\x00 not really a pdf"),
    ("report.pdf", pdf(b"<< /S /JavaScript /JS (app.alert(1)) >>\n")),
    ("report.docx", b"plain text pretending to be docx"),
    ("report.docx", docx(macro=True)),
    ("report.docm", docx(macro=True)),
    ("report.html", b"<script>alert(1)</script>"),
])
def test_dangerous_uploads_are_rejected(app, name, data):
    c = login(app, "s1001")
    upload(app, c, 1, name, data)
    assert query(app, "SELECT COUNT(*) FROM submissions")[0][0] == 0
    assert query(app, "SELECT COUNT(*) FROM audit_log WHERE event = 'upload_rejected'")[0][0] == 1


def test_oversized_upload_is_rejected(app):
    c = login(app, "s1001")
    r = upload(app, c, 1, "big.pdf", pdf(b"0" * (11 * 1024 * 1024)))
    assert r.status_code == 413
    assert query(app, "SELECT COUNT(*) FROM submissions")[0][0] == 0


def test_valid_upload_is_stored_safely_and_served_as_attachment(app, tmp_path):
    c = login(app, "s1001")
    upload(app, c, 1, "../../evil<script>.pdf", pdf())
    row = query(app, "SELECT * FROM submissions")[0]
    assert re.fullmatch(r"[0-9a-f]{32}", row["stored_name"])       # random name, no extension
    assert (tmp_path / "uploads" / row["stored_name"]).exists()     # and not under static/
    assert "<" not in row["display_name"] and "/" not in row["display_name"]
    r = get(c, f"/submissions/{row['id']}/download")
    assert r.status_code == 200
    assert r.headers["Content-Disposition"].startswith("attachment; filename=s1001_assignment1.pdf")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in r.headers["Content-Security-Policy"]
    assert upload(app, c, 1, "ok.docx", docx()).status_code == 302  # resubmission replaces
    assert query(app, "SELECT COUNT(*), MAX(ext) FROM submissions")[0][:] == (1, "docx")


def test_submission_access_is_limited_to_owner_and_course_lecturer(app):
    upload(app, login(app, "s1001"), 1, "a.pdf", pdf())   # assignment 1 = CS301 (l2001)
    sid = query(app, "SELECT id FROM submissions")[0][0]
    assert get(login(app, "s1002"), f"/submissions/{sid}/download").status_code == 404
    assert get(login(app, "l2002"), f"/submissions/{sid}/download").status_code == 404
    assert get(login(app, "l2001"), f"/submissions/{sid}/download").status_code == 200
    # s1003 is not enrolled in CS301, so cannot submit to its assignment
    assert upload(app, login(app, "s1003"), 1, "a.pdf", pdf()).status_code == 404


# --------------------------------------- story 3: messaging (T1565.002)
def test_messages_only_between_lecturer_and_their_students(app):
    c = login(app, "s1002")  # enrolled in CS301 only (lecturer l2001)
    ok = post(c, "/messages/new", {"to": uid(app, "l2001"), "subject": "Hi", "body": "Question"},
              form_page="/messages/new")
    assert ok.status_code == 302
    for target in ("l2002", "s1001"):  # not my lecturer / another student
        r = post(c, "/messages/new", {"to": uid(app, target), "subject": "Hi", "body": "x"},
                 form_page="/messages/new")
        assert r.status_code == 400
    assert query(app, "SELECT COUNT(*) FROM messages WHERE sender_id = ?", (uid(app, "s1002"),))[0][0] == 1


def test_cannot_read_someone_elses_message_and_body_is_escaped(app):
    lecturer = login(app, "l2001")
    post(lecturer, "/messages/new", {"to": uid(app, "s1002"), "subject": "Feedback",
                                     "body": "<script>alert('x')</script>"}, form_page="/messages/new")
    mid = query(app, "SELECT MAX(id) FROM messages")[0][0]
    assert get(login(app, "s1001"), f"/messages/{mid}").status_code == 404
    html = get(login(app, "s1002"), f"/messages/{mid}").get_data(as_text=True)
    assert "&lt;script&gt;" in html and "<script>alert" not in html


# ------------------------------------------ story 4: profile (T1078 / IDOR)
def test_student_cannot_view_other_students_or_lecturer_pages(app):
    c = login(app, "s1002")
    for path in (f"/students/{uid(app, 's1001')}", "/students", "/submissions"):
        assert get(c, path).status_code == 404
    assert query(app, "SELECT COUNT(*) FROM audit_log WHERE event = 'authz_denied'")[0][0] == 3


def test_lecturer_sees_only_students_they_teach(app):
    c = login(app, "l2001")  # teaches s1001, s1002 -- not s1003
    page = get(c, f"/students/{uid(app, 's1001')}").get_data(as_text=True)
    assert "aisha.tan@student.example.edu" in page
    assert get(c, f"/students/{uid(app, 's1003')}").status_code == 404
    assert get(c, f"/students/{uid(app, 'l2002')}").status_code == 404


def test_profile_update_ignores_extra_fields_and_validates(app):
    c = login(app, "s1001")
    form = {"email": "aisha.tan@student.example.edu", "phone": "+60 12-555 9999", "address": "1 Jalan Ilmu",
            "emergency_contact": "Mei Tan +60 12-555 7777",
            "role": "lecturer", "id": uid(app, "s1002"), "username": "admin"}  # tampering
    assert post(c, "/profile", form, form_page="/profile").status_code == 302
    me, other = query(app, "SELECT role, username, phone FROM users WHERE username IN ('s1001', 's1002') ORDER BY username")
    assert tuple(me) == ("student", "s1001", "+60 12-555 9999")
    assert other["phone"] == "+60 12-555 0102"
    bad = post(c, "/profile", form | {"phone": "<img src=x onerror=alert(1)>"}, form_page="/profile")
    assert bad.status_code == 400


def test_email_change_requires_current_password(app):
    c = login(app, "s1001")
    form = {"email": "new@example.com", "phone": "+60 12-555 0101", "address": "", "emergency_contact": ""}
    assert post(c, "/profile", form, form_page="/profile").status_code == 400
    assert post(c, "/profile", form | {"current_password": PASSWORD}, form_page="/profile").status_code == 302
    assert query(app, "SELECT email FROM users WHERE username = 's1001'")[0][0] == "new@example.com"


def test_password_change_enforces_policy_and_signs_out_other_sessions(app):
    c, other = login(app, "s1003"), None
    time.sleep(0)  # same user, second device
    with app.app_context():  # allow a second TOTP login inside the same 30 s step
        db.get_db().execute("UPDATE users SET totp_last_counter = 0 WHERE username = 's1003'")
        db.get_db().commit()
    other = login(app, "s1003")
    weak = post(c, "/account/security", {"current_password": PASSWORD, "new_password": "short",
                                         "confirm_password": "short"}, form_page="/account/security")
    assert weak.status_code == 400
    good = post(c, "/account/security", {"current_password": PASSWORD, "new_password": "four random words here",
                                         "confirm_password": "four random words here"}, form_page="/account/security")
    assert good.status_code == 302
    assert get(other, "/grades").status_code == 302   # other device signed out
    assert get(c, "/grades").status_code == 200


def test_audit_log_never_contains_secrets(app):
    c = client_for(app)
    post(c, "/login", {"username": "s1001\nevent=forged", "password": "Sup3rSecretValue!"})
    rows = query(app, "SELECT detail FROM audit_log")
    assert rows and all("Sup3rSecretValue" not in r[0] and "\n" not in r[0] for r in rows)


def test_reply_prefill_is_authorised(app):
    mid = query(app, "SELECT id FROM messages")[0][0]          # seeded: l2001 -> s1001
    page = get(login(app, "s1001"), f"/messages/new?reply={mid}").get_data(as_text=True)
    assert 'value="Re: Welcome to CS301"' in page
    assert get(login(app, "s1002"), f"/messages/new?reply={mid}").status_code == 404
