import importlib.util
from pathlib import Path
import secrets
from unittest.mock import patch


def load_portal(monkeypatch):
    monkeypatch.setenv("PROTECTED_APP_SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("PORTAL_PASSWORD", "synthetic-portal-password")
    monkeypatch.setenv("SHIELD_API_CLIENT_ID", "test-client")
    monkeypatch.setenv("SHIELD_API_CLIENT_SECRET", "synthetic-client-secret")
    spec = importlib.util.spec_from_file_location(
        "portal_under_test", Path(__file__).resolve().parents[1] / "protected_app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_portal_fails_closed_and_authenticates_client(monkeypatch):
    portal = load_portal(monkeypatch)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"success": "false"}'

    with patch.object(
        portal.urllib.request, "urlopen", return_value=Response()
    ) as call:
        assert portal.verify_with_shield("student", "123456")[0] is False
        assert (
            call.call_args.args[0].get_header("Authorization")
            == "Bearer synthetic-client-secret"
        )

    class InvalidResponse(Response):
        def read(self):
            return b"not json"

    with patch.object(portal.urllib.request, "urlopen", return_value=InvalidResponse()):
        assert portal.verify_with_shield("student", "123456")[0] is False


def test_portal_csrf_and_template_render(monkeypatch):
    portal = load_portal(monkeypatch)
    client = portal.app.test_client()
    assert client.get("/").status_code == 200
    assert client.post("/", data={}).status_code == 400
    assert client.get("/logout").status_code == 405
