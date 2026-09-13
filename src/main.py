import argparse
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from src.bootstrap import RuntimeSettings, build_application


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate PAM MVP configuration and build the application",
    )
    parser.add_argument("--auth-db", type=Path, required=True)
    parser.add_argument("--config-db", type=Path, required=True)
    parser.add_argument("--vault-db", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--vault-key", type=Path, required=True)
    parser.add_argument("--audit-key", type=Path, required=True)
    parser.add_argument(
        "--max-session-seconds",
        type=float,
        required=True,
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(arguments)
    settings = RuntimeSettings(
        auth_db_path=parsed.auth_db,
        config_db_path=parsed.config_db,
        vault_db_path=parsed.vault_db,
        audit_db_path=parsed.audit_db,
        vault_key_path=parsed.vault_key,
        audit_integrity_key_path=parsed.audit_key,
        max_session_duration=timedelta(
            seconds=parsed.max_session_seconds
        ),
    )
    build_application(settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
