# Northfield Student Portal

A university student portal built from a threat model: students view grades and attendance, submit assignments, message lecturers and update their contact details; lecturers review submissions, see their own students' contact details and send messages.

Start with **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — it contains the data flow diagrams, trust boundaries, the ATT&CK → ASVS 5.0 → code → test mapping, and the coding and UI principles.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
PORTAL_DEV=1 .venv/bin/python manage.py init-db
```

```bash
PORTAL_DEV=1 .venv/bin/python run.py
```

Open http://127.0.0.1:5000 and sign in with one of the IDs and one-time passwords printed by `init-db`:

| ID | Role | Courses |
|---|---|---|
| s1001 | Student | CS301, CS205 |
| s1002 | Student | CS301 |
| s1003 | Student | CS205 |
| l2001 | Lecturer | CS301 |
| l2002 | Lecturer | CS205 |

First sign-in asks you to set up two-step verification with any authenticator app. For later sign-ins without a phone, a demo-only helper prints the current code:

```bash
PORTAL_DEV=1 .venv/bin/python manage.py totp s1001
```

`PORTAL_DEV=1` allows plain HTTP on localhost. Without it the app only answers over HTTPS and uses `__Host-` Secure cookies; `deploy/nginx.conf` shows the TLS 1.2/1.3 proxy in front of it.

## Verify the controls

```bash
.venv/bin/python -m pytest -q
```

29 tests, one or more per threat in the model. To see the audit trail after trying things by hand:

```bash
PORTAL_DEV=1 .venv/bin/python manage.py audit
```

Things worth trying for a demo: three wrong passwords (CAPTCHA appears), five (sign-in pauses); upload a renamed `.exe` as `.pdf`; as `s1002` open `/students/1`; as `l2001` open `/students/3`.

## Layout

| Path | Contents |
|---|---|
| `portal/security.py` | Password hashing, sessions, CSRF, throttling, MFA, authorisation helpers, audit log |
| `portal/auth.py` | Login, MFA enrolment and verification, logout, password change |
| `portal/views.py` | Grades, assignments, messages, profile, lecturer pages |
| `portal/uploads.py` | Upload policy and file validation |
| `portal/__init__.py` | App factory, HTTPS enforcement, security headers, error pages |
| `portal/templates`, `portal/static` | UI (no inline script or style) |
| `docs/` | Threat model, DFDs (`make_dfd.py` regenerates them), screenshots |
| `deploy/nginx.conf` | TLS termination example |
| `tests/test_security.py` | Security regression tests |
