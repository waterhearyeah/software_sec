"""SQLite access + schema + demo seed data.

All queries in the app use bound parameters (?) -- never string formatting --
so user input cannot change the structure of a SQL statement (ASVS 1.2.4).
"""
import sqlite3
import time

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('student', 'lecturer')),
    pw_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    emergency_contact TEXT NOT NULL DEFAULT '',
    totp_secret TEXT,
    totp_last_counter INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER,
    last_login_ip TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,           -- SHA-256 of the cookie value
    user_id INTEGER REFERENCES users(id),
    state TEXT NOT NULL DEFAULT 'anon',    -- anon | mfa_pending | enrol | full
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    captcha_answer TEXT,
    pending_totp TEXT,
    mfa_failures INTEGER NOT NULL DEFAULT 0,
    flash TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    username_key TEXT NOT NULL,
    ip TEXT NOT NULL,
    ts INTEGER NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempt_user ON login_attempts(username_key, ts);
CREATE INDEX IF NOT EXISTS idx_attempt_ip ON login_attempts(ip, ts);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    user_id INTEGER,
    ip TEXT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    lecturer_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS enrolments (
    student_id INTEGER NOT NULL REFERENCES users(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    PRIMARY KEY (student_id, course_id)
);
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES users(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    item TEXT NOT NULL,
    score REAL NOT NULL,
    max_score REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES users(id),
    course_id INTEGER NOT NULL REFERENCES courses(id),
    day TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('present', 'absent', 'late'))
);
CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    title TEXT NOT NULL,
    due TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    stored_name TEXT NOT NULL,     -- random server-generated name on disk
    display_name TEXT NOT NULL,    -- sanitised original name, display only
    ext TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    scan_status TEXT NOT NULL,     -- clean | unscanned
    uploaded_at INTEGER NOT NULL,
    UNIQUE (assignment_id, student_id)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    read_at INTEGER
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_schema():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


DEMO_USERS = [
    # username, role, full name, email, phone
    ("s1001", "student", "Aisha Tan", "aisha.tan@student.example.edu", "+60 12-555 0101"),
    ("s1002", "student", "Daniel Lim", "daniel.lim@student.example.edu", "+60 12-555 0102"),
    ("s1003", "student", "Priya Nair", "priya.nair@student.example.edu", "+60 12-555 0103"),
    ("l2001", "lecturer", "Dr. Farah Ismail", "farah.ismail@staff.example.edu", "+60 3-5550 2001"),
    ("l2002", "lecturer", "Dr. Marcus Wong", "marcus.wong@staff.example.edu", "+60 3-5550 2002"),
]


def seed(password_for):
    """Insert demo data. `password_for(username)` returns the *hashed* password."""
    db = get_db()
    if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return False
    ids = {}
    for username, role, name, email, phone in DEMO_USERS:
        cur = db.execute(
            "INSERT INTO users (username, role, pw_hash, full_name, email, phone)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (username, role, password_for(username), name, email, phone),
        )
        ids[username] = cur.lastrowid
    courses = [
        ("CS301", "Secure Software Development", "l2001", ["s1001", "s1002"]),
        ("CS205", "Database Systems", "l2002", ["s1001", "s1003"]),
    ]
    marks = {"s1001": (82, 74), "s1002": (65, 71), "s1003": (90, 88)}
    for code, title, lecturer, students in courses:
        cid = db.execute(
            "INSERT INTO courses (code, title, lecturer_id) VALUES (?, ?, ?)",
            (code, title, ids[lecturer]),
        ).lastrowid
        db.execute(
            "INSERT INTO assignments (course_id, title, due) VALUES (?, ?, ?)",
            (cid, f"{code} Lab 1 report", "2026-12-04"),
        )
        db.execute(
            "INSERT INTO assignments (course_id, title, due) VALUES (?, ?, ?)",
            (cid, f"{code} Project proposal", "2026-12-18"),
        )
        for s in students:
            db.execute("INSERT INTO enrolments VALUES (?, ?)", (ids[s], cid))
            quiz, mid = marks[s]
            db.execute(
                "INSERT INTO grades (student_id, course_id, item, score, max_score)"
                " VALUES (?, ?, 'Quiz 1', ?, 100), (?, ?, 'Midterm', ?, 100)",
                (ids[s], cid, quiz, ids[s], cid, mid),
            )
            for i, day in enumerate(["2026-11-02", "2026-11-04", "2026-11-09", "2026-11-11"]):
                status = "absent" if (i == 2 and s == "s1002") else ("late" if i == 1 and s == "s1001" else "present")
                db.execute(
                    "INSERT INTO attendance (student_id, course_id, day, status) VALUES (?, ?, ?, ?)",
                    (ids[s], cid, day, status),
                )
    db.execute(
        "INSERT INTO messages (sender_id, recipient_id, subject, body, sent_at) VALUES (?, ?, ?, ?, ?)",
        (ids["l2001"], ids["s1001"], "Welcome to CS301",
         "Hi Aisha,\n\nLab 1 is now open. Please submit your report as a PDF or DOCX.\n\nDr. Farah", int(time.time())),
    )
    db.commit()
    return True
