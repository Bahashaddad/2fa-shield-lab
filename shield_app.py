import re
import os
import click
import base64
import io
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import pyotp
import qrcode
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


APP_NAME = "2FA Shield"
APP_TAGLINE = "Secure Multi-Factor Authentication Gateway"
BASE_DIR = Path(__file__).resolve().parent
DATABASE = str(BASE_DIR / "instance" / "shield.db")
OTP_INTERVAL = 30
MAX_OTP_FAILURES = 5
OTP_FAILURE_WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 30
RECOVERY_CODE_COUNT = 10

app = Flask(
    __name__,
    template_folder="templates_shield",
    static_folder="static",
    root_path=str(BASE_DIR),
)
app.config.update(
    SECRET_KEY=os.environ.get("SHIELD_SECRET_KEY", ""),
    DATABASE=os.environ.get("SHIELD_DATABASE", DATABASE),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=32 * 1024,
    TRUSTED_HOSTS=["localhost", "127.0.0.1"],
)
if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError(
        "Set SHIELD_SECRET_KEY to a locally generated value of at least 32 characters."
    )
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def column_names(table):
    rows = get_db().execute(f"PRAGMA table_info({table})").fetchall()
    return [row["name"] for row in rows]


def init_db():
    db = get_db()
    db.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            totp_secret TEXT NOT NULL UNIQUE,
            mfa_enrolled INTEGER NOT NULL DEFAULT 0,
            last_used_totp_step INTEGER,
            locked_until TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS otp_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            attempted_at TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS protected_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            app_name TEXT NOT NULL,
            account_identifier TEXT,
            category TEXT,
            description TEXT,
            app_url TEXT,
            totp_secret TEXT NOT NULL,
            api_client_id TEXT UNIQUE NOT NULL,
            api_client_secret_hash TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            last_used_totp_step INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS verification_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protected_app_id INTEGER,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL,
            reason TEXT NOT NULL,
            FOREIGN KEY(protected_app_id) REFERENCES protected_apps(id) ON DELETE SET NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT NOT NULL,
            event_type TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS admin_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_protected_apps_user ON protected_apps(user_id);
        CREATE INDEX IF NOT EXISTS idx_verification_attempts_app_time ON verification_attempts(protected_app_id, attempted_at);
        """
    )
    db.commit()


def hash_secret(value):
    return bcrypt.hashpw(value.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_secret(value, stored_hash):
    try:
        if not 1 <= len(value.encode("utf-8")) <= 72:
            return False
        return bcrypt.checkpw(value.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def client_ip():
    return request.remote_addr or "unknown"


def audit(event_type, result, user=None, details="", username=None):
    db = get_db()
    now = iso_now()
    db.execute(
        """
        INSERT INTO audit_logs
            (user_id, username, ip_address, event_type, result, details, created_at, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"] if user else None,
            user["username"] if user else username or request.form.get("username"),
            client_ip(),
            event_type,
            result,
            details,
            now,
            now,
        ),
    )
    db.commit()


def notify_admins(user, message, severity="warning"):
    get_db().execute(
        """
        INSERT INTO admin_notifications (user_id, message, severity, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user["id"] if user else None, message, severity, iso_now()),
    )
    get_db().commit()


def user_by_username(username):
    return (
        get_db()
        .execute("SELECT * FROM users WHERE username = ?", (username,))
        .fetchone()
    )


def user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def is_admin(user):
    return user and user["role"] == "admin"


def generate_unique_totp_secret(table="users"):
    while True:
        secret = pyotp.random_base32()
        if (
            not get_db()
            .execute(f"SELECT 1 FROM {table} WHERE totp_secret = ?", (secret,))
            .fetchone()
        ):
            return secret


@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(username, password):
    """Create a local administrator without predictable credentials."""
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username)
        or not 12 <= len(password.encode("utf-8")) <= 72
    ):
        raise click.ClickException(
            "Use a 3-64 character username and a 12-72 byte password."
        )
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username,password_hash,role,totp_secret,created_at) VALUES (?,?,'admin',?,?)",
            (username, hash_secret(password), generate_unique_totp_secret(), iso_now()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise click.ClickException("That username is unavailable.") from None
    click.echo("Administrator created. Enroll MFA on first login.")


def is_locked(user):
    if not user["locked_until"]:
        return False
    try:
        return datetime.fromisoformat(user["locked_until"]) > utc_now()
    except ValueError:
        return False


def lock_user(user):
    locked_until = (utc_now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(
        timespec="seconds"
    )
    get_db().execute(
        "UPDATE users SET locked_until = ? WHERE id = ?", (locked_until, user["id"])
    )
    get_db().commit()
    notify_admins(
        user,
        f"User {user['username']} locked until {locked_until} after MFA failures.",
        "critical",
    )
    audit(
        "lockout", "locked", user, f"Exceeded {MAX_OTP_FAILURES} failed MFA attempts."
    )


def recent_otp_failures(user_id):
    cutoff = (utc_now() - timedelta(minutes=OTP_FAILURE_WINDOW_MINUTES)).isoformat(
        timespec="seconds"
    )
    row = (
        get_db()
        .execute(
            "SELECT COUNT(*) AS count FROM otp_failures WHERE user_id = ? AND attempted_at >= ?",
            (user_id, cutoff),
        )
        .fetchone()
    )
    return row["count"]


def record_otp_failure(user, details):
    get_db().execute(
        "INSERT INTO otp_failures (user_id, attempted_at, ip_address) VALUES (?, ?, ?)",
        (user["id"], iso_now(), client_ip()),
    )
    get_db().commit()
    audit("otp_failure", "failure", user, details)
    if recent_otp_failures(user["id"]) >= MAX_OTP_FAILURES:
        lock_user(user)


def clear_otp_failures(user_id):
    get_db().execute("DELETE FROM otp_failures WHERE user_id = ?", (user_id,))
    get_db().commit()


def generate_recovery_codes():
    return [
        secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:12].upper()
        for _ in range(RECOVERY_CODE_COUNT)
    ]


def replace_recovery_codes(user_id):
    codes = generate_recovery_codes()
    db = get_db()
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    for code in codes:
        db.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            (user_id, hash_secret(code), iso_now()),
        )
    db.commit()
    return codes


def make_user_qr_data_uri(user):
    uri = pyotp.TOTP(
        user["totp_secret"], digits=6, interval=OTP_INTERVAL
    ).provisioning_uri(name=user["username"], issuer_name=APP_NAME)
    return qr_data_uri(uri)


def make_app_qr_data_uri(protected_app):
    label = protected_app["account_identifier"] or protected_app["app_name"]
    uri = pyotp.TOTP(
        protected_app["totp_secret"], digits=6, interval=OTP_INTERVAL
    ).provisioning_uri(
        name=label, issuer_name=f"{APP_NAME}: {protected_app['app_name']}"
    )
    return qr_data_uri(uri)


def qr_data_uri(uri):
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode(
        "ascii"
    )


def current_totp_code(secret):
    return pyotp.TOTP(secret, digits=6, interval=OTP_INTERVAL).now()


def matching_totp_step(secret, code):
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret, digits=6, interval=OTP_INTERVAL)
    current = int(time.time()) // OTP_INTERVAL
    for step in (current, current - 1):
        if secrets.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = user_by_id(session["user_id"])
        if not is_admin(user):
            audit("admin_action", "denied", user, "Non-admin attempted admin access.")
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def normal_user_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if session.get("pre_mfa_user_id"):
                return redirect(url_for("verify_mfa"))
            return redirect(url_for("login"))
        user = user_by_id(session["user_id"])
        if not user:
            session.clear()
            return redirect(url_for("login"))
        if is_admin(user):
            return redirect(url_for("admin_dashboard"))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_current_user():
    g.user = user_by_id(session["user_id"]) if session.get("user_id") else None


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("admin_dashboard" if is_admin(g.user) else "dashboard"))
    return render_template("index.html", app_tagline=APP_TAGLINE)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username)
            or not 12 <= len(password.encode("utf-8")) <= 72
            or len(email) > 254
        ):
            flash(
                "Use a 3-64 character username and a password of 12-72 UTF-8 bytes.",
                "warning",
            )
            return render_template("register.html")
        if user_by_username(username):
            flash("That username is already registered.", "danger")
            return render_template("register.html")
        get_db().execute(
            """
            INSERT INTO users (username, email, password_hash, role, totp_secret, created_at)
            VALUES (?, ?, ?, 'user', ?, ?)
            """,
            (
                username,
                email,
                hash_secret(password),
                generate_unique_totp_secret("users"),
                iso_now(),
            ),
        )
        get_db().commit()
        user = user_by_username(username)
        audit(
            "registration",
            "success",
            user,
            "User registered; Shield MFA enrollment required.",
        )
        session.clear()
        session["pre_mfa_user_id"] = user["id"]
        session["pre_mfa_expires"] = time.time() + 300
        return redirect(url_for("setup_mfa"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = user_by_username(username)
        if not user or not check_secret(password, user["password_hash"]):
            audit(
                "login_attempt",
                "failure",
                user,
                "Invalid username or password.",
                username=username,
            )
            flash("Invalid username or password.", "danger")
            return render_template("login.html")
        if is_locked(user):
            audit(
                "login_attempt",
                "locked",
                user,
                f"Account locked until {user['locked_until']}.",
            )
            flash(
                "Account is locked. Contact an administrator or try again later.",
                "danger",
            )
            return render_template("login.html")
        audit("login_attempt", "password_ok", user, "Password accepted; MFA required.")
        session.clear()
        session["pre_mfa_user_id"] = user["id"]
        session["pre_mfa_expires"] = time.time() + 300
        return redirect(url_for("verify_mfa" if user["mfa_enrolled"] else "setup_mfa"))
    return render_template("login.html")


@app.route("/mfa/setup", methods=["GET", "POST"])
def setup_mfa():
    user = user_by_id(session.get("pre_mfa_user_id"))
    if not user:
        return redirect(url_for("login"))
    if is_locked(user):
        session.clear()
        return redirect(url_for("login"))
    if user["mfa_enrolled"]:
        return redirect(url_for("verify_mfa"))
    if request.method == "POST":
        step = matching_totp_step(user["totp_secret"], request.form.get("otp", ""))
        if step is None:
            record_otp_failure(user, "Invalid TOTP during enrollment.")
            flash("Invalid authenticator code.", "danger")
        else:
            codes = replace_recovery_codes(user["id"])
            get_db().execute(
                "UPDATE users SET mfa_enrolled = 1, last_used_totp_step = ? WHERE id = ?",
                (step, user["id"]),
            )
            get_db().commit()
            audit(
                "enrollment",
                "success",
                user,
                "Shield MFA enrolled and recovery codes generated.",
            )
            session.permanent = True
            session["user_id"] = user["id"]
            session.pop("pre_mfa_user_id", None)
            clear_otp_failures(user["id"])
            return render_template("recovery_codes.html", codes=codes)
    return render_template(
        "setup_mfa.html", user=user, qr_data=make_user_qr_data_uri(user)
    )


@app.route("/mfa/verify", methods=["GET", "POST"])
def verify_mfa():
    user = user_by_id(session.get("pre_mfa_user_id"))
    if not user:
        return redirect(url_for("login"))
    if is_locked(user):
        audit(
            "mfa_challenge",
            "locked",
            user,
            f"Account locked until {user['locked_until']}.",
        )
        return render_template(
            "verify_mfa.html", locked=True, locked_until=user["locked_until"]
        )
    if request.method == "POST":
        if recent_otp_failures(user["id"]) >= MAX_OTP_FAILURES:
            lock_user(user)
            flash(
                "Too many failed MFA attempts. Account locked for 30 minutes.", "danger"
            )
            return redirect(url_for("login"))
        otp = request.form.get("otp", "").strip().replace(" ", "")
        recovery_code = (
            request.form.get("recovery_code", "").strip().replace(" ", "").upper()
        )
        if otp:
            step = matching_totp_step(user["totp_secret"], otp)
            if step is None:
                record_otp_failure(user, "Invalid TOTP code.")
            elif (
                user["last_used_totp_step"] is not None
                and step <= user["last_used_totp_step"]
            ):
                record_otp_failure(user, "Rejected reused TOTP time-step.")
            else:
                if not consume_totp("users", user["id"], step):
                    flash("MFA verification failed.", "danger")
                    return render_template("verify_mfa.html", locked=False)
                clear_otp_failures(user["id"])
                audit("otp_success", "success", user, "Shield user TOTP verified.")
                session.permanent = True
                session["user_id"] = user["id"]
                session.pop("pre_mfa_user_id", None)
                return redirect(
                    url_for("admin_dashboard" if is_admin(user) else "dashboard")
                )
        elif recovery_code:
            rows = (
                get_db()
                .execute(
                    "SELECT * FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                    (user["id"],),
                )
                .fetchall()
            )
            for row in rows:
                if check_secret(recovery_code, row["code_hash"]):
                    cursor = get_db().execute(
                        "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
                        (iso_now(), row["id"]),
                    )
                    get_db().commit()
                    if cursor.rowcount != 1:
                        break
                    clear_otp_failures(user["id"])
                    audit(
                        "recovery_code_usage",
                        "success",
                        user,
                        "Single-use recovery code accepted.",
                    )
                    session.permanent = True
                    session["user_id"] = user["id"]
                    session.pop("pre_mfa_user_id", None)
                    return redirect(
                        url_for("admin_dashboard" if is_admin(user) else "dashboard")
                    )
            record_otp_failure(user, "Invalid recovery code during MFA.")
        else:
            flash("Enter an authenticator code or recovery code.", "warning")
            return render_template("verify_mfa.html", locked=False)
        flash("MFA verification failed.", "danger")
    return render_template("verify_mfa.html", locked=False)


@app.route("/dashboard")
@login_required
def dashboard():
    if is_admin(g.user):
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    remaining_codes = db.execute(
        "SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (g.user["id"],),
    ).fetchone()["count"]
    recent_events = db.execute(
        "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 8",
        (g.user["id"],),
    ).fetchall()
    protected_apps = db.execute(
        "SELECT * FROM protected_apps WHERE user_id = ? ORDER BY created_at DESC LIMIT 4",
        (g.user["id"],),
    ).fetchall()
    protected_app_count = db.execute(
        "SELECT COUNT(*) AS count FROM protected_apps WHERE user_id = ?",
        (g.user["id"],),
    ).fetchone()["count"]
    return render_template(
        "dashboard.html",
        remaining_codes=remaining_codes,
        recent_events=recent_events,
        protected_app_count=protected_app_count,
        protected_apps=apps_with_codes(protected_apps),
    )


def app_form_data():
    app_url = request.form.get("app_url", "").strip()
    if app_url and not app_url.lower().startswith(("http://", "https://")):
        app_url = ""
    status = request.form.get("status", "active").strip()
    if status not in {"active", "disabled"}:
        status = "active"
    return {
        "app_name": request.form.get("app_name", "").strip(),
        "account_identifier": request.form.get("account_identifier", "").strip(),
        "category": request.form.get("category", "").strip() or "Other",
        "description": request.form.get("description", "").strip(),
        "app_url": app_url,
        "status": status,
    }


def user_protected_app(app_id):
    return (
        get_db()
        .execute(
            "SELECT * FROM protected_apps WHERE id = ? AND user_id = ?",
            (app_id, g.user["id"]),
        )
        .fetchone()
    )


def protected_app_by_client_id(client_id):
    return (
        get_db()
        .execute("SELECT * FROM protected_apps WHERE api_client_id = ?", (client_id,))
        .fetchone()
    )


def apps_with_codes(rows):
    return [
        {**dict(row), "current_code": current_totp_code(row["totp_secret"])}
        for row in rows
    ]


@app.route("/apps")
@normal_user_required
def apps():
    rows = (
        get_db()
        .execute(
            "SELECT * FROM protected_apps WHERE user_id = ? ORDER BY created_at DESC",
            (g.user["id"],),
        )
        .fetchall()
    )
    return render_template("apps.html", apps=apps_with_codes(rows))


@app.route("/apps/new", methods=["GET", "POST"])
@normal_user_required
def new_app():
    if request.method == "POST":
        data = app_form_data()
        if (
            not data["app_name"]
            or not data["account_identifier"]
            or any(len(v) > 500 for v in data.values())
        ):
            flash(
                "App name and account identifier are required; fields must be at most 500 characters.",
                "warning",
            )
            return render_template("app_form.html", protected_app=data, mode="new")
        api_client_id = "shield_" + secrets.token_urlsafe(18).replace("-", "").replace(
            "_", ""
        )
        api_client_secret = secrets.token_urlsafe(32)
        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO protected_apps
                (user_id, app_name, account_identifier, category, description, app_url,
                 totp_secret, api_client_id, api_client_secret_hash, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g.user["id"],
                data["app_name"],
                data["account_identifier"],
                data["category"],
                data["description"],
                data["app_url"],
                generate_unique_totp_secret("protected_apps"),
                api_client_id,
                hash_secret(api_client_secret),
                data["status"],
                iso_now(),
            ),
        )
        db.commit()
        app_id = cursor.lastrowid
        audit(
            "PROTECTED_APP_CREATED",
            "success",
            g.user,
            f"Protected app created: {data['app_name']}",
        )
        protected_app = user_protected_app(app_id)
        return render_template(
            "app_secret_once.html",
            protected_app=protected_app,
            api_client_secret=api_client_secret,
        )
    return render_template("app_form.html", protected_app=None, mode="new")


@app.route("/apps/<int:app_id>")
@normal_user_required
def app_detail(app_id):
    protected_app = user_protected_app(app_id)
    if not protected_app:
        flash("Protected app not found or access denied.", "danger")
        return redirect(url_for("apps"))
    return render_template(
        "app_detail.html",
        protected_app=protected_app,
        current_code=current_totp_code(protected_app["totp_secret"]),
        qr_data=make_app_qr_data_uri(protected_app),
    )


@app.route("/apps/edit/<int:app_id>", methods=["GET", "POST"])
@normal_user_required
def edit_app(app_id):
    protected_app = user_protected_app(app_id)
    if not protected_app:
        flash("Protected app not found or access denied.", "danger")
        return redirect(url_for("apps"))
    if request.method == "POST":
        data = app_form_data()
        if (
            not data["app_name"]
            or not data["account_identifier"]
            or any(len(v) > 500 for v in data.values())
        ):
            flash(
                "App name and account identifier are required; fields must be at most 500 characters.",
                "warning",
            )
            return render_template(
                "app_form.html",
                protected_app={**dict(protected_app), **data},
                mode="edit",
            )
        get_db().execute(
            """
            UPDATE protected_apps
            SET app_name = ?, account_identifier = ?, category = ?, description = ?,
                app_url = ?, status = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                data["app_name"],
                data["account_identifier"],
                data["category"],
                data["description"],
                data["app_url"],
                data["status"],
                iso_now(),
                app_id,
                g.user["id"],
            ),
        )
        get_db().commit()
        audit(
            "PROTECTED_APP_UPDATED",
            "success",
            g.user,
            f"Protected app updated: {data['app_name']}",
        )
        flash("Protected app updated.", "success")
        return redirect(url_for("app_detail", app_id=app_id))
    return render_template("app_form.html", protected_app=protected_app, mode="edit")


@app.route("/apps/delete/<int:app_id>", methods=["POST"])
@normal_user_required
def delete_app(app_id):
    protected_app = user_protected_app(app_id)
    if not protected_app:
        flash("Protected app not found or access denied.", "danger")
        return redirect(url_for("apps"))
    get_db().execute(
        "DELETE FROM protected_apps WHERE id = ? AND user_id = ?",
        (app_id, g.user["id"]),
    )
    get_db().commit()
    audit(
        "PROTECTED_APP_DELETED",
        "success",
        g.user,
        f"Protected app deleted: {protected_app['app_name']}",
    )
    flash("Protected app deleted.", "success")
    return redirect(url_for("apps"))


def recent_failed_verifications(protected_app_id):
    cutoff = (utc_now() - timedelta(minutes=OTP_FAILURE_WINDOW_MINUTES)).isoformat(
        timespec="seconds"
    )
    row = (
        get_db()
        .execute(
            """
        SELECT COUNT(*) AS count FROM verification_attempts
        WHERE protected_app_id = ? AND success = 0 AND attempted_at >= ?
        """,
            (protected_app_id, cutoff),
        )
        .fetchone()
    )
    return row["count"]


def record_verification_attempt(protected_app, app_username, success, reason):
    user = user_by_id(protected_app["user_id"]) if protected_app else None
    get_db().execute(
        """
        INSERT INTO verification_attempts
            (protected_app_id, user_id, username, ip_address, attempted_at, success, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            protected_app["id"] if protected_app else None,
            protected_app["user_id"] if protected_app else None,
            app_username,
            client_ip(),
            iso_now(),
            1 if success else 0,
            reason,
        ),
    )
    get_db().commit()
    audit(
        "PROTECTED_APP_CODE_VERIFIED" if success else "PROTECTED_APP_CODE_FAILED",
        "success" if success else "failure",
        user,
        reason,
        username=app_username,
    )


@app.route("/api/verify-code", methods=["POST"])
@csrf.exempt
def verify_code_api():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, message="Expected a JSON object"), 400
    api_client_id = str(payload.get("api_client_id", "")).strip()
    app_username = str(payload.get("app_username", "")).strip()
    code = str(payload.get("code", "")).strip()
    protected_app = protected_app_by_client_id(api_client_id)
    authorization = request.headers.get("Authorization", "")
    client_secret = (
        authorization.removeprefix("Bearer ")
        if authorization.startswith("Bearer ")
        else ""
    )
    if not protected_app or not check_secret(
        client_secret, protected_app["api_client_secret_hash"]
    ):
        return jsonify(success=False, message="Invalid client credentials"), 401
    if (
        protected_app["status"] != "active"
        or app_username != protected_app["account_identifier"]
    ):
        return jsonify(success=False, message="Verification denied"), 403
    if recent_failed_verifications(protected_app["id"]) >= MAX_OTP_FAILURES:
        record_verification_attempt(
            protected_app, app_username, False, "Verification rate limited."
        )
        return jsonify(
            success=False, message="2FA verification is temporarily rate limited"
        ), 429
    step = matching_totp_step(protected_app["totp_secret"], code)
    if step is None:
        record_verification_attempt(
            protected_app, app_username, False, "Invalid or expired 2FA code."
        )
        return jsonify(success=False, message="Invalid or expired 2FA code"), 200
    if (
        protected_app["last_used_totp_step"] is not None
        and step <= protected_app["last_used_totp_step"]
    ):
        record_verification_attempt(
            protected_app, app_username, False, "Rejected replayed 2FA code."
        )
        return jsonify(success=False, message="Invalid or expired 2FA code"), 200
    if not consume_totp("protected_apps", protected_app["id"], step):
        return jsonify(success=False, message="Invalid or expired 2FA code"), 200
    record_verification_attempt(
        protected_app, app_username, True, "2FA code verified by 2FA Shield."
    )
    return jsonify(success=True, message="2FA code verified by 2FA Shield")


@app.route("/audit-logs")
@login_required
def audit_logs():
    if is_admin(g.user):
        logs = (
            get_db()
            .execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 300")
            .fetchall()
        )
    else:
        logs = (
            get_db()
            .execute(
                "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
                (g.user["id"],),
            )
            .fetchall()
        )
    return render_template("audit_logs.html", logs=logs)


@app.route("/recovery-codes")
@login_required
def recovery_codes():
    flash(
        "Recovery codes are shown only once immediately after enrollment or regeneration.",
        "info",
    )
    return redirect(url_for("dashboard"))


@app.route("/recovery-codes/regenerate", methods=["POST"])
@login_required
def regenerate_recovery_codes():
    if is_locked(g.user):
        abort(403)
    step = matching_totp_step(g.user["totp_secret"], request.form.get("otp", ""))
    if step is None or (
        g.user["last_used_totp_step"] is not None
        and step <= g.user["last_used_totp_step"]
    ):
        record_otp_failure(g.user, "Invalid TOTP during recovery-code regeneration.")
        flash(
            "Valid authenticator code required to regenerate recovery codes.", "danger"
        )
        return redirect(url_for("dashboard"))
    if not consume_totp("users", g.user["id"], step):
        abort(409)
    codes = replace_recovery_codes(g.user["id"])
    audit(
        "recovery_code_regeneration",
        "success",
        g.user,
        "Generated exactly 10 new recovery codes.",
    )
    return render_template("recovery_codes.html", codes=codes)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return login()


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute(
        """
        SELECT u.*,
            (SELECT COUNT(*) FROM recovery_codes rc WHERE rc.user_id = u.id AND rc.used_at IS NULL) AS recovery_remaining
        FROM users u ORDER BY u.created_at DESC
        """
    ).fetchall()
    logs = db.execute(
        "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    attempts = db.execute(
        """
        SELECT va.*, pa.app_name
        FROM verification_attempts va
        LEFT JOIN protected_apps pa ON pa.id = va.protected_app_id
        ORDER BY va.attempted_at DESC LIMIT 100
        """
    ).fetchall()
    notifications = db.execute(
        "SELECT * FROM admin_notifications ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    stats = {
        "total_users": len(users),
        "mfa_enabled": sum(1 for user in users if user["mfa_enrolled"]),
        "locked_accounts": sum(1 for user in users if is_locked(user)),
        "protected_apps": db.execute(
            "SELECT COUNT(*) AS count FROM protected_apps"
        ).fetchone()["count"],
        "failed_verifications": db.execute(
            "SELECT COUNT(*) AS count FROM verification_attempts WHERE success = 0"
        ).fetchone()["count"],
    }
    return render_template(
        "admin_dashboard.html",
        users=users,
        logs=logs,
        attempts=attempts,
        notifications=notifications,
        stats=stats,
    )


@app.route("/admin/unlock/<int:user_id>", methods=["POST"])
@admin_required
def admin_unlock(user_id):
    user = user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    get_db().execute("UPDATE users SET locked_until = NULL WHERE id = ?", (user_id,))
    get_db().execute("DELETE FROM otp_failures WHERE user_id = ?", (user_id,))
    get_db().commit()
    audit(
        "admin_action",
        "success",
        g.user,
        f"Unlocked user {user['username']} ({user_id}).",
    )
    flash(f"Unlocked {user['username']}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.context_processor
def inject_helpers():
    return {"is_admin": is_admin, "otp_interval": OTP_INTERVAL}


@app.cli.command("init-db")
def init_database_command():
    """Initialize an empty local database."""
    init_db()
    click.echo("Database initialized; no accounts were seeded.")


def consume_totp(table, record_id, step):
    if table not in {"users", "protected_apps"}:
        raise ValueError("Unsupported TOTP table")
    db = get_db()
    cursor = db.execute(
        f"UPDATE {table} SET last_used_totp_step=? WHERE id=? AND (last_used_totp_step IS NULL OR last_used_totp_step < ?)",
        (step, record_id, step),
    )
    db.commit()
    return cursor.rowcount == 1


@app.before_request
def request_security():
    if (
        session.get("pre_mfa_user_id")
        and session.get("pre_mfa_expires", 0) < time.time()
    ):
        session.clear()
    if request.method == "POST":
        db = get_db()
        db.execute(
            "CREATE TABLE IF NOT EXISTS request_limits (address TEXT, endpoint TEXT, attempted REAL)"
        )
        now = time.time()
        db.execute("DELETE FROM request_limits WHERE attempted < ?", (now - 60,))
        key = request.endpoint or "unknown"
        count = db.execute(
            "SELECT COUNT(*) FROM request_limits WHERE address=? AND endpoint=?",
            (client_ip(), key),
        ).fetchone()[0]
        if count >= 30:
            db.commit()
            abort(429)
        db.execute("INSERT INTO request_limits VALUES (?,?,?)", (client_ip(), key, now))
        db.commit()


@app.after_request
def response_security(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
