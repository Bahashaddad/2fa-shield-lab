import json
import os
import secrets
import urllib.error
import urllib.request
import urllib.parse
from functools import wraps
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask import abort

from flask import Flask, flash, redirect, render_template, request, session, url_for


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()

SHIELD_VERIFY_URL = os.environ.get(
    "SHIELD_VERIFY_URL", "http://127.0.0.1:5000/api/verify-code"
)
_verify_target = urllib.parse.urlsplit(SHIELD_VERIFY_URL)
if (
    _verify_target.scheme not in {"http", "https"}
    or _verify_target.hostname not in {"127.0.0.1", "localhost"}
    or _verify_target.username
    or _verify_target.password
):
    raise RuntimeError("SHIELD_VERIFY_URL must target a loopback HTTP(S) endpoint.")
API_CLIENT_ID = os.environ.get("SHIELD_API_CLIENT_ID", "").strip()
DEMO_USERNAME = os.environ.get("PORTAL_USERNAME", "student")
DEMO_PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
API_CLIENT_SECRET = os.environ.get("SHIELD_API_CLIENT_SECRET", "")

app = Flask(
    __name__,
    template_folder="templates_protected",
    static_folder="static",
    root_path=os.path.dirname(os.path.abspath(__file__)),
)
app.config.update(
    SECRET_KEY=os.environ.get("PROTECTED_APP_SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=8192,
    TRUSTED_HOSTS=["localhost", "127.0.0.1"],
)
if len(app.secret_key) < 32 or len(DEMO_PASSWORD.encode("utf-8")) < 12:
    raise RuntimeError(
        "Set PROTECTED_APP_SECRET_KEY (32+ characters) and PORTAL_PASSWORD (12+ bytes)."
    )
csrf = CSRFProtect(app)
_login_attempts = {}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("student_authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def verify_with_shield(username, code):
    if not API_CLIENT_ID or not API_CLIENT_SECRET:
        return False, "Protected app API Client ID is not configured."
    payload = json.dumps(
        {
            "api_client_id": API_CLIENT_ID,
            "app_username": username,
            "code": code,
        }
    ).encode("utf-8")
    request_obj = urllib.request.Request(
        SHIELD_VERIFY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + API_CLIENT_SECRET,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body.get("success") is True, body.get(
                "message", "Invalid or expired 2FA code."
            )
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
            return False, body.get("message", "Invalid or expired 2FA code.")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False, "Invalid or expired 2FA code."
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        AttributeError,
    ):
        return False, "2FA Shield verification service is unavailable."


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        import time

        address = request.remote_addr or "unknown"
        now = time.monotonic()
        for key in list(_login_attempts):
            _login_attempts[key] = [t for t in _login_attempts[key] if now - t < 60]
            if not _login_attempts[key]:
                del _login_attempts[key]
        if len(_login_attempts.get(address, [])) >= 10:
            abort(429)
        _login_attempts.setdefault(address, []).append(now)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("code", "").strip().replace(" ", "")
        if username != DEMO_USERNAME or password != DEMO_PASSWORD:
            flash("Invalid username, password, or 2FA code.", "danger")
            return render_template(
                "login.html", api_client_configured=bool(API_CLIENT_ID)
            )
        success, message = verify_with_shield(username, code)
        if not success:
            flash(message if message else "Invalid or expired 2FA code.", "danger")
            return render_template(
                "login.html", api_client_configured=bool(API_CLIENT_ID)
            )
        session.clear()
        session.permanent = True
        session["student_authenticated"] = True
        session["student_username"] = username
        return redirect(url_for("dashboard"))
    return render_template("login.html", api_client_configured=bool(API_CLIENT_ID))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html", username=session.get("student_username", DEMO_USERNAME)
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.after_request
def response_security(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
