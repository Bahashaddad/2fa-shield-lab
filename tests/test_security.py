import time
from concurrent.futures import ThreadPoolExecutor
import pyotp


def pending(client, identity):
    with client.session_transaction() as session:
        session["pre_mfa_user_id"] = identity["id"]
        session["pre_mfa_expires"] = time.time() + 300


def test_enrolled_secret_unavailable_before_mfa(shield, identity):
    client = shield.app.test_client()
    pending(client, identity)
    response = client.get("/mfa/setup")
    assert response.status_code == 302
    assert response.location.endswith("/mfa/verify")
    assert identity["secret"].encode() not in response.data


def test_expired_pending_login_cannot_enroll(shield, identity):
    client = shield.app.test_client()
    with client.session_transaction() as session:
        session["pre_mfa_user_id"] = identity["id"]
        session["pre_mfa_expires"] = 0
    assert client.get("/mfa/setup").location.endswith("/login")


def test_totp_replay_and_concurrent_consumption(shield, identity):
    def consume():
        with shield.app.app_context():
            return shield.consume_totp("users", identity["id"], 12345)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: consume(), range(2))) == [False, True]


def test_recovery_code_single_use(shield, identity):
    with shield.app.app_context():
        codes = shield.replace_recovery_codes(identity["id"])
    client = shield.app.test_client()
    pending(client, identity)
    assert (
        client.post("/mfa/verify", data={"recovery_code": codes[0]}).status_code == 302
    )
    client.post("/logout")
    pending(client, identity)
    response = client.post("/mfa/verify", data={"recovery_code": codes[0]})
    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "user_id" not in session


def test_api_auth_identity_and_replay(shield, identity):
    app_secret = pyotp.random_base32()
    with shield.app.app_context():
        db = shield.get_db()
        db.execute(
            "INSERT INTO protected_apps (user_id,app_name,account_identifier,totp_secret,api_client_id,api_client_secret_hash,created_at) VALUES (1,'test app','student',?,?,?,?)",
            (
                app_secret,
                "test-client",
                shield.hash_secret("synthetic-api-client-secret"),
                shield.iso_now(),
            ),
        )
        db.commit()
    client = shield.app.test_client()
    body = {
        "api_client_id": "test-client",
        "app_username": "student",
        "code": pyotp.TOTP(app_secret).now(),
    }
    assert client.post("/api/verify-code", json=body).status_code == 401
    headers = {"Authorization": "Bearer synthetic-api-client-secret"}
    assert (
        client.post(
            "/api/verify-code", json={**body, "app_username": "other"}, headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post("/api/verify-code", json=body, headers=headers).json["success"]
        is True
    )
    assert (
        client.post("/api/verify-code", json=body, headers=headers).json["success"]
        is False
    )
    assert client.post("/api/verify-code", json=[]).status_code == 400


def test_no_secret_in_creation_url_or_logs(shield, identity):
    client = shield.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = identity["id"]
    response = client.post(
        "/apps/new", data={"app_name": "Portal", "account_identifier": "student"}
    )
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/apps/1/secret?secret=anything").status_code == 404


def test_ownership(shield, identity):
    client = shield.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = identity["id"]
    assert client.get("/apps/9999").status_code == 302
    assert client.get("/admin").status_code == 302


def test_csrf_and_post_logout(shield):
    shield.app.config["WTF_CSRF_ENABLED"] = True
    client = shield.app.test_client()
    assert client.post("/register", data={}).status_code == 400
    assert client.get("/logout").status_code == 405


def test_password_limits_and_no_default_admin(shield):
    with shield.app.app_context():
        assert shield.get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert not shield.check_secret("x" * 73, shield.hash_secret("valid password"))


def test_ip_header_not_trusted(shield):
    with shield.app.test_request_context(
        headers={"X-Forwarded-For": "203.0.113.5"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        assert shield.client_ip() == "127.0.0.1"
