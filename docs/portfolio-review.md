# Portfolio review: 2FA Shield Lab

Prepared 2026-11-02. Original input: `2fa-shield.zip`. The owner approved separate copies and improvements, and confirmed contributor publication agreement. Originals remain unchanged. Phase 4 approval is recorded; Phase 5 changes are in this copy. Phase 6 is bounded by the checks and remaining gates below.

## 1. Actual purpose

Two Flask applications demonstrate local password/TOTP authentication, recovery codes, and client verification. The legacy app only gated records/links, not external websites.

## 2. Quality and public suitability

The original had understandable helpers, bcrypt hashing, parameterized queries, and ownership checks, but a critical enrollment bypass, included authentication databases, duplicated versions, and no tests. The copied edition retains the active two-app design and adds focused hardening. It remains a local educational service.

## 3. Security and evidence concerns

Severity is a qualitative project-context assessment, not a CVSS calculation. Confirmed source behavior is distinguished from unavailable evidence and potential privacy risks.

| Severity | Affected original file/area | Problem and impact | Remediation/status | Before publication? |
|---|---|---|---|---|
| Critical | shield_app.py: setup_mfa; legacy app.py | An enrolled seed was returned during password-only authentication. | Guard enrolled accounts; test direct-route access. Applied. | Yes; fixed in copy |
| High | instance/shield.db; twofa_shield.db | Populated seeds, password hashes, recovery hashes, and activity were archived. | Originals excluded; generate new local databases. Reset exposed credentials and re-enroll factors before reuse. | Yes; original material excluded |
| High | shield_app.py: verify_code_api; protected_app.py | API client secret unused; account identity not checked. | Authenticate client and bind app_username to account_identifier. Applied and tested. | Yes; fixed in copy |
| High | shield_app.py: new_app/app_secret_once | API secret passed in a URL. | Direct creation response; old secret route removed; no-store and no-referrer. | Yes; fixed in copy |
| High | OTP and recovery verification | Non-atomic single-use checks permitted concurrent redemption. | Conditional database updates; concurrent TOTP regression and recovery replay tests. | Yes; fixed in copy |
| High | Administrator seed and portal account | Predictable credentials were embedded. | Explicit prompted admin initialization and environment-configured portal password. | Yes; fixed in copy |
| Medium | Forms, cookies, throttling, dependency pins | Missing CSRF, inconsistent session/throttle configuration, old dependency set. | CSRF, explicit lifetimes, no-store, bounded inputs, lightweight limits, updated full runtime pins. | Yes; applied with lab limits |
| Medium | Seed storage, dev servers, CDN assets | Plaintext seeds at rest and development-only infrastructure remain. | Keep loopback/synthetic-only; use real key management and hardened deployment if scope changes. | Documented lab boundary; not production-ready |

## 4. File-by-file disposition

See `docs/file-classification.csv` for every original archive entry/file and its KEEP/MODIFY/REMOVE/PRIVATE/OPTIONAL disposition. Originals containing sensitive material are not placed in the upload copy. New files are additions, not original coursework artifacts.

## 5. Complete resulting tree

The full tree is recorded in `docs/directory-tree.txt`. Runtime/cache files are excluded.

## 6. README assessment and complete replacement

Original README embedded predictable credentials, omitted the enrollment bypass and API authentication gap, overstated strict expiry and replay guarantees, and did not explain stale browser codes. Its complete replacement is README.md in this repository; installation now requires explicit initialization and locally supplied secrets.

The complete improved README is the repository's root `README.md`, rather than a second divergent copy pasted into this report.

## 7. Specific improvements and corrected code

The files in this prepared copy are the exact replacements/additions. `CHANGELOG.md` identifies behavior changes. Source PDFs, runtime data, and credential files were not rewritten in place. Do not interpret new tests or editorial additions as work performed during the original course.

## 8. Before-publication checklist

- [x] Separate copy created; original preserved.
- [x] Public README and clean directory structure provided.
- [x] Runtime data, keys, original identifiers, and unsafe original screenshots excluded.
- [x] MIT license and third-party notice supplied following contributor agreement.
- [ ] Manually inspect a fresh browser demo with synthetic data.
- [ ] Review GitHub Actions results after upload; no hosted run has occurred.
- [ ] Rotate original credentials/factors if exposed or reused; old database deletion alone is insufficient.

Review `docs/verification.md` for exact executed checks and remaining limits. Hosted Actions results and manual review must not be reported as completed merely because a workflow exists.

## 9. Skills and CV wording

Python web development, authentication state transitions, bcrypt/TOTP, SQL-backed event recording, ownership checks, security regression testing. No SIEM deployment, enterprise IAM, or production security certification is demonstrated.

Suggested wording: “Developed an academic Flask MFA lab with TOTP, hashed recovery codes, and a simulated client; subsequently added regression tests and remediated enrollment, API-authentication, and replay flaws.”

## 10. Honest original score

| Dimension | Original score / 10 |
|---|---|
| Code quality | 5 |
| Security | 2 |
| Documentation | 5 |
| Organization | 4 |
| Professional presentation | 4 |
| Portfolio value | 6 |

**4.3/10 original**. Scores assess supplied evidence, not personal ability. Documentation-only artifacts are not assigned invented code/security scores. Improvements do not establish a certified security posture or guarantee a hiring outcome.

## Repository metadata

- Name: `2fa-shield-lab`
- Description: Educational Flask MFA lab with TOTP, recovery codes, authenticated client verification, and security regression tests.
- Topics: python, flask, sqlite, totp, multi-factor-authentication, application-security, security-testing
- Release: consider `v0.1.0` after the remaining verification and rights gates pass. Documentation/data corrections should have a changelog entry and updated version; do not retag a changed release.
- Screenshots: optional, synthetic and sanitized only. No original screenshots are cleared for public reuse.
- License: MIT for original code/documentation; third-party rights remain separate. Underlying data provenance may impose additional limits.
