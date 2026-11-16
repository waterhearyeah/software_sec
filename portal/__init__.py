"""Student Portal -- application factory, security headers, error handling."""
import logging
import os
import time

from flask import Flask, g, redirect, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, security, uploads


def create_app(test_config=None):
    app = Flask(__name__)
    dev = os.environ.get("PORTAL_DEV") == "1"
    data_dir = os.environ.get("PORTAL_DATA", os.path.join(os.getcwd(), "instance"))
    app.config.update(
        DATA_DIR=data_dir,
        # Secure by default: plain-HTTP mode must be asked for explicitly.
        HTTPS_ONLY=not dev,
        IDLE_TIMEOUT=15 * 60,           # ASVS 7.3.1
        ABSOLUTE_TIMEOUT=8 * 60 * 60,   # ASVS 7.3.2
        # Hard cap enforced before the body is parsed (ASVS 5.2.1).
        MAX_CONTENT_LENGTH=uploads.MAX_BYTES + 64 * 1024,
        MAX_FORM_MEMORY_SIZE=256 * 1024,
    )
    app.config.update(test_config or {})
    data_dir = app.config["DATA_DIR"]
    app.config["DB_PATH"] = os.path.join(data_dir, "portal.db")
    app.config["UPLOAD_DIR"] = os.path.join(data_dir, "uploads")  # outside static/
    os.makedirs(app.config["UPLOAD_DIR"], mode=0o700, exist_ok=True)
    # "__Host-" pins the cookie to this exact host, Secure, path=/ (ASVS 3.3.1).
    app.config["COOKIE_NAME"] = "__Host-sid" if app.config["HTTPS_ONLY"] else "sid"

    if os.environ.get("PORTAL_BEHIND_PROXY") == "1":
        # Trust exactly one proxy hop for client IP / scheme (see deploy/nginx.conf).
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_schema()

    @app.before_request
    def _before():
        if app.config["HTTPS_ONLY"] and not request.is_secure:
            # Never serve content over plain HTTP (ASVS 12.2.1).
            return redirect(request.url.replace("http://", "https://", 1), code=308)
        return security.load_session()

    @app.after_request
    def _after(resp):
        cfg = app.config
        if g.get("new_cookie"):
            resp.set_cookie(cfg["COOKIE_NAME"], g.new_cookie, httponly=True,
                            secure=cfg["HTTPS_ONLY"], samesite="Strict", path="/")
        h = resp.headers
        # No inline script/style anywhere, so injected markup cannot execute.
        h.setdefault("Content-Security-Policy",
                     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                     "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if cfg["HTTPS_ONLY"]:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            h["Cache-Control"] = "no-store"  # grades etc. must not linger in caches
        return resp

    @app.template_filter("dt")
    def _dt(ts):
        return time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(ts))

    @app.context_processor
    def _ctx():
        return {
            "user": g.get("user"),
            "csrf_token": g.sess["csrf"] if g.get("sess") else "",
            "flashes": security.pop_flashes(),
            "idle_timeout": app.config["IDLE_TIMEOUT"],
            "https_only": app.config["HTTPS_ONLY"],
        }

    messages = {
        400: ("Request could not be processed", "Please go back, refresh the page and try again."),
        404: ("Page not found", "The page does not exist or you do not have access to it."),
        405: ("Page not found", "The page does not exist or you do not have access to it."),
        413: ("File too large", "The largest file you can upload is 10 MB."),
        429: ("Too many attempts", "Please wait a few minutes before trying again."),
        500: ("Something went wrong", "The problem has been logged. Please try again later."),
    }

    def _error(err):
        # Generic pages only: no stack traces, paths or SQL (ASVS 16.5.1).
        code = getattr(err, "code", 500)
        if code not in messages:
            code = 500
        if code == 500:
            app.logger.exception("unhandled error")
        title, text = messages[code]
        return render_template("error.html", title=title, text=text), code

    for code in messages:
        app.register_error_handler(code, _error)
    app.register_error_handler(Exception, _error)

    from .auth import bp as auth_bp
    from .views import bp as views_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    return app
