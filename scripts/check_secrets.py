"""Fail closed when detect-secrets finds a candidate in tracked files."""

import subprocess
from pathlib import Path

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import default_settings


def main() -> int:
    try:
        tracked = subprocess.run(
            (
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ),
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
    except (OSError, subprocess.CalledProcessError):
        print("Secret scan: FAILED (tracked files could not be enumerated).")
        return 1
    filenames = [
        value.decode("utf-8", errors="surrogateescape")
        for value in tracked
        if value
        and Path(value.decode("utf-8", errors="surrogateescape")).is_file()
    ]

    try:
        with default_settings():
            candidates = SecretsCollection()
            for filename in filenames:
                candidates.scan_file(filename)
    except Exception:
        print("Secret scan: FAILED (files could not be scanned).")
        return 1

    if candidates.data:
        print("Secret scan: FAILED (candidate locations withheld).")
        return 1
    print("Secret scan: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
