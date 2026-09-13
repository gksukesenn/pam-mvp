from contextlib import closing
from pathlib import Path
import sqlite3

import pytest

from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.config.errors import (
    ConfigStorageError,
    DuplicateTargetError,
    MalformedTargetError,
)
from src.infrastructure.config.sqlite_target_repository import (
    SQLiteTargetRepository,
)
from src.ports.access_dependencies import TargetRepository


def make_repository(
    tmp_path: Path,
) -> tuple[SQLiteTargetRepository, Path]:
    database_path = tmp_path / "config.db"
    return SQLiteTargetRepository(database_path), database_path


def make_target(
    target_id: str = "target-001",
    *,
    enabled: bool = True,
) -> Target:
    return Target(
        id=target_id,
        name="production-server",
        host="pam-node.example.test",
        port=2222,
        expected_host_key=HostKeyFingerprint("SHA256:target-key-001"),
        enabled=enabled,
    )


def read_rows(database_path: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, name, host, port, expected_host_key, enabled
            FROM targets
            ORDER BY id
            """
        ).fetchall()


def update_target_value(
    database_path: Path,
    column: str,
    value: object,
) -> None:
    statements = {
        "port": "UPDATE targets SET port = ? WHERE id = ?",
        "expected_host_key": (
            "UPDATE targets SET expected_host_key = ? WHERE id = ?"
        ),
        "enabled": "UPDATE targets SET enabled = ? WHERE id = ?",
    }
    assert column in statements
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(statements[column], (value, "target-001"))


@pytest.mark.parametrize("enabled", [True, False])
def test_target_round_trips_exact_fields_and_enabled_state(
    tmp_path: Path,
    enabled: bool,
):
    repository, database_path = make_repository(tmp_path)
    target = make_target(enabled=enabled)

    repository.store(target)

    assert repository.get(target.id) == target
    assert repository.get(target.id).expected_host_key == (
        HostKeyFingerprint("SHA256:target-key-001")
    )
    assert read_rows(database_path) == [
        (
            "target-001",
            "production-server",
            "pam-node.example.test",
            2222,
            "SHA256:target-key-001",
            int(enabled),
        )
    ]


def test_target_schema_is_exact_and_contains_no_secret_fields(tmp_path: Path):
    _, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(targets)"
            ).fetchall()
        ]

    assert columns == [
        "id",
        "name",
        "host",
        "port",
        "expected_host_key",
        "enabled",
    ]


def test_duplicate_target_id_is_rejected_without_overwrite(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_target(enabled=False))
    original = read_rows(database_path)
    replacement = Target(
        id="target-001",
        name="replacement",
        host="replacement.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:replacement"),
    )

    with pytest.raises(
        DuplicateTargetError,
        match="target id already exists",
    ):
        repository.store(replacement)

    assert read_rows(database_path) == original


def test_missing_target_returns_none(tmp_path: Path):
    repository, _ = make_repository(tmp_path)

    assert repository.get("missing-target") is None


def test_malformed_fingerprint_fails_explicitly(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_target())
    update_target_value(database_path, "expected_host_key", "not-sha256")

    with pytest.raises(
        MalformedTargetError,
        match="target contains invalid stored values",
    ):
        repository.get("target-001")


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("port", 0),
        ("port", 65536),
        ("port", "not-a-port"),
        ("enabled", -1),
        ("enabled", 2),
        ("enabled", "yes"),
    ],
)
def test_malformed_port_or_enabled_value_fails_explicitly(
    tmp_path: Path,
    column: str,
    value: object,
):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_target())
    update_target_value(database_path, column, value)

    with pytest.raises(MalformedTargetError):
        repository.get("target-001")


def test_sql_looking_target_id_is_only_a_value(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    malicious_id = "target' OR 1=1; DROP TABLE targets; --"
    target = make_target(malicious_id)
    repository.store(target)
    repository.store(make_target("target-ordinary"))

    assert repository.get(malicious_id) == target
    assert repository.get("' OR 1=1 --") is None
    assert len(read_rows(database_path)) == 2


def test_target_storage_failure_is_explicit(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE targets")

    with pytest.raises(
        ConfigStorageError,
        match="target could not be loaded",
    ):
        repository.get("target-001")


def test_sqlite_target_repository_satisfies_port(tmp_path: Path):
    repository, _ = make_repository(tmp_path)
    target_repository: TargetRepository = repository

    assert target_repository.get("target-001") is None
