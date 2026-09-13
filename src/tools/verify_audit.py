"""Verify one lab audit chain without displaying audit material."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.security.file_key_provider import FileKeyProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify PAM lab audit-chain integrity",
    )
    parser.add_argument("--runtime-dir", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    runtime_dir = build_parser().parse_args(arguments).runtime_dir
    audit_database = runtime_dir / "audit.db"
    audit_key = runtime_dir / "audit.key"
    try:
        if (
            not audit_database.is_file()
            or audit_database.stat().st_size == 0
            or not audit_key.is_file()
            or audit_key.stat().st_size == 0
        ):
            raise ValueError
        repository = SQLiteAuditRepository(
            audit_database,
            FileKeyProvider(audit_key),
        )
        repository.verify_integrity()
    except Exception:
        print("Audit integrity: FAILED")
        return 1

    print("Audit integrity: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
