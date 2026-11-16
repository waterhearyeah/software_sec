"""Local development server:  PORTAL_DEV=1 python run.py

Without PORTAL_DEV=1 the app refuses plain HTTP (redirects to HTTPS) and
uses Secure, __Host- prefixed cookies -- deploy it behind deploy/nginx.conf.
"""
from portal import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)  # debug stays off: no interactive debugger
