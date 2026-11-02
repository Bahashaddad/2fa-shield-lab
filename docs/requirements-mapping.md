# Implementation mapping

| Area | Implemented evidence | Boundary |
|---|---|---|
| Authentication | Password login, guarded enrollment, TOTP challenge | Local synthetic users only |
| Authorization | Per-owner app queries and administrator decorator | Targeted tests, not full formal verification |
| API clients | Hashed client secret check and account binding | Loopback demo transport |
| Replay | Conditional TOTP-step update and recovery redemption | Targeted replay/concurrency regression tests |
| Recovery | Ten random codes stored as bcrypt hashes | Not a complete account-recovery service |
| Throttling | MFA failures/lockouts and local request limits | Not distributed abuse prevention |
| Confidentiality | Secret-free URL creation flow and no-store responses | Database seeds remain plaintext |
| Audit | Application event tables and role-restricted views | Local records; no tamper-proof SIEM |

SMS, email delivery, production SSO, and arbitrary website protection are not implemented.
