# Local lab trust boundaries

Assets include passwords, TOTP seeds, recovery material where implemented, API credentials, signing keys, and audit records. Browser cookies are signed, not encrypted. Seeds and plaintext credentials must not be stored in those cookies. The SQLite database is a sensitive local asset, not a public fixture.

The intended environment is one user-controlled host, loopback interfaces, synthetic users, and no production integrations. Threats considered include password-only access to enrollment, replay, unauthorized account access, CSRF, malformed input, secret disclosure through URLs/logs, and unsafe HTML/template evaluation.

Tests provide targeted regression evidence. They do not establish production suitability, full OWASP coverage, resistance to a compromised host, or independent penetration-test certification. Plaintext seed storage, lightweight throttling, and single-process development-server assumptions remain limitations.
