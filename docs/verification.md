# Verification — 2026-11-02

**Status: prepared local educational candidate; complete manual browser/hosted-CI review before public release.**

- Fresh isolated Python 3.12 environment installed the exact supplied `requirements-dev.txt` successfully.
- `pip check`: no broken requirements.
- 12 security/integration tests passed, including client authentication headers, malformed-response denial, CSRF, enrollment protection, identity binding, replay, ownership, and concurrent TOTP consumption.
- A real-CSRF test-client workflow completed registration, QR enrollment, recovery-code result rendering, app creation, and key portal pages. Initialization and prompted user/admin commands passed via Flask's CLI test runner.
- Critical-error Ruff checks passed. They do not imply every optional style/security rule was enabled.
- `pip-audit 2.10.1` reported no known vulnerabilities for the 14 pinned runtime packages. Full JSON is `dependency-audit.json`; this is a point-in-time advisory result, not a guarantee.
- Readable source/templates and an exact replacement README are included. Tests use generated keys and isolated synthetic data.

Remaining: manual browser appearance/demo review, hosted CI, and original credential/factor rotation if exposed or reused. This is not a production deployment or penetration-test certification.

## Common publication checks and limits

- Original inputs were accessed read-only and all seven original SHA-256 hashes were rechecked unchanged.
- Prepared files were compared against 69 sensitive values from original environment/database material and nine identifier-shaped values from original reports, without printing those values. No matches remained in the public candidates.
- No original private keys, `.env`, runtime databases/logs, executable tools, raw PDFs, or original XLSX files are included.
- The publication guard passed against Git-tracked snapshots of all seven candidates. It is a limited guard, not a complete commercial secret scanner or proof of absence.
- No Git history was supplied or imported. Existing repositories/history must be reviewed separately if these files are added to them.
- No GitHub repository, hosted Actions run, release, CV change, or LinkedIn update was published.
- Contributor publication agreement was confirmed by the owner. Third-party data/service/source rights remain separate.
- Inspection used source/static review, report text extraction, report previews where available, workbook cell/object inventory, and targeted execution of the prepared copies. Original compiled Python was not decompiled, `mkcert.exe` was not executed or reverse engineered, and screenshots/embedded objects were not all individually cleared. Exclusion of originals is deliberate; no claim of exhaustive visual clearance is made.
