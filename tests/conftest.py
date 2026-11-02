import importlib.util
from pathlib import Path
import secrets
import pytest


@pytest.fixture
def shield(monkeypatch, tmp_path):
    monkeypatch.setenv("SHIELD_SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("SHIELD_DATABASE", str(tmp_path / "shield.db"))
    spec = importlib.util.spec_from_file_location(
        "shield_under_test", Path(__file__).resolve().parents[1] / "shield_app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with module.app.app_context():
        module.init_db()
    return module


@pytest.fixture
def identity(shield):
    import pyotp

    secret = pyotp.random_base32()
    with shield.app.app_context():
        db = shield.get_db()
        db.execute(
            "INSERT INTO users (username,password_hash,role,totp_secret,mfa_enrolled,created_at) VALUES (?,?,'user',?,1,?)",
            (
                "test-user",
                shield.hash_secret("synthetic-test-password"),
                secret,
                shield.iso_now(),
            ),
        )
        db.commit()
    return {"id": 1, "secret": secret}
