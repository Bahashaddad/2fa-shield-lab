"""Fail if common private/generated artifacts enter the tracked publication set."""

from pathlib import Path
import re
import subprocess

files = (
    subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True)
    .stdout.decode()
    .split("\0")
)
errors = []
for name in filter(None, files):
    p = Path(name)
    if p.is_symlink():
        errors.append(name + ": symlink requires manual review")
        continue
    if (
        p.name == ".env"
        or (p.name.startswith(".env.") and p.name != ".env.example")
        or p.suffix.lower()
        in {
            ".db",
            ".sqlite",
            ".sqlite3",
            ".pem",
            ".key",
            ".pfx",
            ".p12",
            ".pyc",
            ".log",
        }
        or any(x in p.parts for x in {".venv", "__pycache__", ".pytest_cache"})
    ):
        errors.append(name + ": private/generated path")
    if p.is_file():
        data = p.read_bytes()
        # Build the sentinel to avoid matching this guard's own source.
        if re.search(b"-----BEGIN " + b"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data):
            errors.append(name + ": private-key content")
        if re.search(
            rb"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}",
            data,
        ):
            errors.append(name + ": credential-shaped content")
if errors:
    raise SystemExit("Publication guard failed:\n" + "\n".join(errors))
print("Tracked-file publication guard passed. This is not a complete secret scanner.")
