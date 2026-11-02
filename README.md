# 2FA Shield Lab

An educational two-application Flask lab exploring TOTP authentication, recovery codes, application-owned verification requests, and security regression testing.

This is a loopback-only demonstration using synthetic accounts. It is not a production authentication service, and adding a protected-app record does not add MFA to an external website.

## Overview

Shield runs on `http://127.0.0.1:5000`. A simulated student portal runs on `http://127.0.0.1:5001` and checks a locally configured password before requesting code verification from Shield. Each protected-app record belongs to a Shield user and has its own TOTP seed and API credentials.

## Features

- Registration, bcrypt password hashing, first-time authenticator enrollment, and MFA login.
- Ten random recovery codes stored as bcrypt hashes; conditional single-use redemption.
- Protected-app ownership checks and authenticated verification API calls.
- Atomic TOTP-step consumption and replay rejection.
- MFA failure tracking, temporary lockouts, and basic local request throttling.
- Administrator unlock actions and security-event records.
- CSRF-protected browser forms and no-store responses.

## Technologies and layout

Python 3.12, Flask, Flask-WTF, SQLite, bcrypt, PyOTP, qrcode/Pillow, Jinja, Bootstrap, and JavaScript.

```text
shield_app.py           Shield service, database helpers, and CLI initialization
protected_app.py        Simulated portal and authenticated API integration
templates_shield/      Shield views
templates_protected/   Portal views
static/                Shared CSS and countdown script
tests/                 Security regression tests
docs/                  Threat model, demo, and implementation notes
requirements.txt       Pinned runtime dependencies, including transitives
requirements-dev.txt   Test, lint, and dependency-audit tools
```

## Installation

From the repository directory, using Python 3.12:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

The dependency set was resolved on Windows with Python 3.12. Linux installation is checked by the supplied GitHub Actions workflow when it runs; a workflow file alone is not a completed CI run.

## Configuration and initialization

Generate local session keys; do not reuse published examples or commit values:

```powershell
$env:SHIELD_SECRET_KEY = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.\.venv\Scripts\python.exe -m flask --app shield_app init-db
.\.venv\Scripts\python.exe -m flask --app shield_app create-admin
.\.venv\Scripts\python.exe shield_app.py
```

Administrator creation prompts for a local username and password. There is no seeded administrator. Keep `SHIELD_SECRET_KEY` stable for the local session; generating a new key invalidates existing cookies.

Register a normal Shield user, enroll an authenticator, and save the recovery codes privately. As that user, create a protected-app record with account identifier `student`. Copy the generated client ID and one-time client secret privately.

In a second terminal:

```powershell
$env:PROTECTED_APP_SECRET_KEY = (.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
$env:PORTAL_USERNAME = "student"
$env:PORTAL_PASSWORD = [System.Net.NetworkCredential]::new("", (Read-Host "Local demo password (12+ bytes)" -AsSecureString)).Password
$env:SHIELD_API_CLIENT_ID = Read-Host "Local client ID"
$env:SHIELD_API_CLIENT_SECRET = [System.Net.NetworkCredential]::new("", (Read-Host "Local client secret" -AsSecureString)).Password
.\.venv\Scripts\python.exe protected_app.py
```

Use synthetic credentials only. Environment variables can be inspected by processes with sufficient local privileges. The example file documents variable names; Shield does not automatically load `.env`. The portal's small local loader supports `.env`, which must remain private.

| Variable | Purpose |
|---|---|
| `SHIELD_SECRET_KEY` | Required Shield cookie-signing key, at least 32 characters |
| `SHIELD_DATABASE` | Optional path; defaults to `instance/shield.db` |
| `PROTECTED_APP_SECRET_KEY` | Required portal cookie-signing key, at least 32 characters |
| `PORTAL_USERNAME` | Portal account identifier, defaults to `student` |
| `PORTAL_PASSWORD` | Required local demonstration password, at least 12 UTF-8 bytes |
| `SHIELD_API_CLIENT_ID` / `SHIELD_API_CLIENT_SECRET` | Protected-app API credentials |
| `SHIELD_VERIFY_URL` | Defaults to the loopback Shield verification endpoint |

## Usage

Open the portal, enter the local demonstration account and a current protected-app code. Correct verification grants access; a used code or wrong account identity is rejected. Inspect Shield audit views using synthetic activity. The API uses JSON fields `api_client_id`, `app_username`, and `code`, plus `Authorization: Bearer <local-client-secret>`.

The page countdown does not fetch new codes. Reload the Shield page after a time step changes. The verifier accepts the current and preceding 30-second time step; do not describe every code as expiring exactly 30 seconds after display.

## Checks

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m pip_audit --disable-pip --no-deps -r requirements.txt
```

Tests use isolated databases and generated test signing keys. The CI workflow runs tests, critical-error linting, dependency auditing, and a publication-content check.

## Security boundaries and limitations

- Both applications use Flask development servers and loopback HTTP. Do not bind them to a LAN or internet interface. Cookies are intentionally not marked Secure for this HTTP-only local demo.
- TOTP seeds remain plaintext in the local SQLite database. A database disclosure defeats the affected factors. No production key management is implemented.
- The portal uses one synthetic account; it is not a multi-tenant identity system.
- Browser-displayed protected-app codes are a teaching mechanism, not a separate trusted device.
- Request throttling is intentionally lightweight. The portal limiter is per-process and not a distributed abuse-control system.
- Bootstrap assets load from a third-party CDN; the CSP restricts their source, but SRI and offline asset delivery remain future work.
- Automated tests are targeted regression evidence, not a penetration-test certification.

Never publish seeds, QR codes, recovery codes, API secrets, local passwords, databases, or logs. Use only owned or explicitly authorized test environments.

## Future work

Separate application construction from global configuration, improve offline asset delivery, introduce separately managed seed encryption, and extend integration/concurrency tests. These are not claimed existing features.

## Authorship and license

Original academic contributors: Baha'a Aldeen Shaddad and Tamer Alomari. See [NOTICE.md](NOTICE.md) for the distinction between coursework and later improvements. Original code and portfolio documentation use the [MIT license](LICENSE); dependencies retain their licenses.
