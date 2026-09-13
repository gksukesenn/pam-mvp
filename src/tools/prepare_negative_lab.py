"""Prepare isolated, one-shot negative-security lab runtimes."""

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import sqlite3
import sys


SCENARIOS = (
    "deny",
    "disabled-target",
    "disabled-account",
    "bad-host-key",
    "tampered-audit",
)
REQUIRED_RUNTIME_FILES = (
    "vault.key",
    "audit.key",
    "auth.db",
    "config.db",
    "vault.db",
)
OPTIONAL_RUNTIME_FILES = ("audit.db",)
BAD_HOST_KEY_FINGERPRINT = (
    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
OWNER_ONLY_FILE_MODE = 0o600
OWNER_ONLY_DIRECTORY_MODE = 0o700


class NegativeLabPreparationError(Exception):
    """Raised when an isolated negative lab cannot be prepared safely."""


@dataclass(frozen=True)
class NegativeLabConfig:
    source: Path
    destination: Path
    scenario: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare an isolated PAM negative-security lab runtime",
        epilog=(
            "The destination must be a new direct child of the source "
            "runtime's sibling scenarios directory."
        ),
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    return parser


def prepare_negative_lab(config: NegativeLabConfig) -> None:
    if not isinstance(config, NegativeLabConfig):
        raise TypeError("config must be NegativeLabConfig")

    source, destination = _validate_paths(config)
    source_files = _validate_source(source, config.scenario)
    _create_private_destination(destination)
    try:
        for source_file in source_files:
            _copy_private_file(source_file, destination / source_file.name)
        if config.scenario == "tampered-audit":
            _tamper_copied_audit(destination / "audit.db")
        else:
            _mutate_copied_config(
                destination / "config.db",
                config.scenario,
            )
    except NegativeLabPreparationError:
        raise
    except Exception:
        raise NegativeLabPreparationError(
            "scenario preparation failed; inspect and remove the destination"
        ) from None


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = build_parser().parse_args(arguments)
    try:
        prepare_negative_lab(
            NegativeLabConfig(
                source=parsed.source,
                destination=parsed.destination,
                scenario=parsed.scenario,
            )
        )
    except NegativeLabPreparationError as error:
        print(f"Scenario preparation failed: {error}", file=sys.stderr)
        return 1

    print("Negative lab scenario prepared.")
    print(f"Scenario: {parsed.scenario}")
    print(f"Destination: {parsed.destination}")
    return 0


def _validate_paths(config: NegativeLabConfig) -> tuple[Path, Path]:
    if (
        not isinstance(config.source, Path)
        or not isinstance(config.destination, Path)
        or config.scenario not in SCENARIOS
    ):
        raise NegativeLabPreparationError("scenario configuration is invalid")

    try:
        source = config.source.resolve(strict=False)
        destination = config.destination.resolve(strict=False)
    except (OSError, RuntimeError):
        raise NegativeLabPreparationError(
            "source or destination path could not be resolved safely"
        ) from None
    if source.name != "lab" or source.parent.name != "runtime":
        raise NegativeLabPreparationError(
            "source must be the runtime/lab baseline"
        )
    scenarios_root = source.parent / "scenarios"
    if destination == source or source in destination.parents:
        raise NegativeLabPreparationError(
            "destination must not be the baseline runtime or one of its children"
        )
    if destination.parent != scenarios_root:
        raise NegativeLabPreparationError(
            "destination must be directly under runtime/scenarios"
        )
    try:
        destination_exists = destination.exists() or destination.is_symlink()
    except OSError:
        raise NegativeLabPreparationError(
            "destination path could not be inspected safely"
        ) from None
    if destination_exists:
        raise NegativeLabPreparationError(
            "destination already exists; remove it manually or choose another"
        )
    return source, destination


def _validate_source(source: Path, scenario: str) -> tuple[Path, ...]:
    try:
        source_is_safe_directory = source.is_dir() and not source.is_symlink()
    except OSError:
        source_is_safe_directory = False
    if not source_is_safe_directory:
        raise NegativeLabPreparationError(
            "source runtime does not exist or is unsafe"
        )

    audit_path = source / "audit.db"
    try:
        audit_exists = audit_path.exists()
    except OSError:
        raise NegativeLabPreparationError(
            "source runtime could not be inspected safely"
        ) from None
    if scenario == "tampered-audit":
        if not audit_exists:
            raise NegativeLabPreparationError(
                "tampered-audit requires an existing baseline audit database"
            )
        filenames = ["audit.key", "audit.db"]
    else:
        filenames = list(REQUIRED_RUNTIME_FILES)
        if audit_exists:
            filenames.extend(OPTIONAL_RUNTIME_FILES)

    source_files = tuple(source / filename for filename in filenames)
    try:
        files_are_safe = all(
            path.is_file() and not path.is_symlink()
            for path in source_files
        )
    except OSError:
        files_are_safe = False
    if not files_are_safe:
        raise NegativeLabPreparationError(
            "source runtime is incomplete or contains unsafe files"
        )
    return source_files


def _create_private_destination(destination: Path) -> None:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir(mode=OWNER_ONLY_DIRECTORY_MODE)
        destination.chmod(OWNER_ONLY_DIRECTORY_MODE)
    except FileExistsError:
        raise NegativeLabPreparationError(
            "destination already exists; remove it manually or choose another"
        ) from None
    except OSError:
        raise NegativeLabPreparationError(
            "destination directory could not be created securely"
        ) from None


def _copy_private_file(source: Path, destination: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            OWNER_ONLY_FILE_MODE,
        )
        os.fchmod(descriptor, OWNER_ONLY_FILE_MODE)
        with source.open("rb") as source_stream:
            with os.fdopen(descriptor, "wb") as destination_stream:
                descriptor = None
                shutil.copyfileobj(source_stream, destination_stream)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise NegativeLabPreparationError(
            "runtime file could not be copied securely"
        ) from None


def _mutate_copied_config(database_path: Path, scenario: str) -> None:
    statements = {
        "deny": (
            "UPDATE access_policies SET effect = ? "
            "WHERE id = ? AND effect = ?",
            ("deny", "policy-001", "allow"),
        ),
        "disabled-target": (
            "UPDATE targets SET enabled = ? WHERE id = ? AND enabled = ?",
            (0, "target-001", 1),
        ),
        "disabled-account": (
            "UPDATE privileged_accounts SET enabled = ? "
            "WHERE id = ? AND enabled = ?",
            (0, "account-001", 1),
        ),
        "bad-host-key": (
            "UPDATE targets SET expected_host_key = ? "
            "WHERE id = ? AND expected_host_key <> ?",
            (
                BAD_HOST_KEY_FINGERPRINT,
                "target-001",
                BAD_HOST_KEY_FINGERPRINT,
            ),
        ),
    }
    if scenario not in statements:
        raise NegativeLabPreparationError("unsupported configuration scenario")

    statement, parameters = statements[scenario]
    try:
        with sqlite3.connect(database_path) as connection:
            cursor = connection.execute(statement, parameters)
            if cursor.rowcount != 1:
                raise NegativeLabPreparationError(
                    "baseline configuration does not match scenario expectations"
                )
    except NegativeLabPreparationError:
        raise
    except sqlite3.Error:
        raise NegativeLabPreparationError(
            "copied configuration could not be changed"
        ) from None


def _tamper_copied_audit(database_path: Path) -> None:
    try:
        with sqlite3.connect(database_path) as connection:
            cursor = connection.execute(
                """
                UPDATE audit_events
                SET target_id = ?
                WHERE sequence_no = (
                    SELECT MIN(sequence_no) FROM audit_events
                ) AND target_id <> ?
                """,
                ("tampered-target-id", "tampered-target-id"),
            )
            if cursor.rowcount != 1:
                raise NegativeLabPreparationError(
                    "baseline audit database has no suitable event to tamper"
                )
    except NegativeLabPreparationError:
        raise
    except sqlite3.Error:
        raise NegativeLabPreparationError(
            "copied audit database could not be changed"
        ) from None


if __name__ == "__main__":
    raise SystemExit(main())
