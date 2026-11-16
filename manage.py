"""Admin commands.

    python manage.py init-db        create tables + demo data, print one-time passwords
    python manage.py totp <user>    DEMO ONLY: print the current MFA code for a user
    python manage.py audit          show the latest audit-log entries
"""
import secrets
import sys
import time

import pyotp

from portal import create_app, db, security

app = create_app()


def init_db():
    issued = {}

    def password_for(username):
        # No shared default password: each account gets a random one, shown once.
        issued[username] = "-".join(secrets.token_hex(3) for _ in range(3))
        return security.hash_password(issued[username])

    if not db.seed(password_for):
        print("Database already contains users; nothing changed.")
        return
    print("Demo accounts created. Initial passwords (shown once, change after first login):\n")
    for user, pw in issued.items():
        print(f"  {user:8} {pw}")
    print("\nEach account sets up two-step verification at first sign-in.")


def totp(username):
    row = db.get_db().execute("SELECT totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not row["totp_secret"]:
        sys.exit("No such user, or MFA not enrolled yet.")
    print(pyotp.TOTP(row["totp_secret"]).now())


def show_audit():
    for r in db.get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 40"):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["ts"]))
        print(f"{stamp}  user={r['user_id'] or '-':<4} ip={r['ip']:<15} {r['event']:<28} {r['detail']}")


if __name__ == "__main__":
    args = sys.argv[1:]
    with app.app_context():
        if args[:1] == ["init-db"]:
            init_db()
        elif args[:1] == ["totp"] and len(args) == 2:
            totp(args[1])
        elif args[:1] == ["audit"]:
            show_audit()
        else:
            sys.exit(__doc__)
