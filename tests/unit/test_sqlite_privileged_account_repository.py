import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.infrastructure.config.errors import (
    AmbiguousPrivilegedAccountError,
    ConfigStorageError,
    DuplicatePrivilegedAccountError,
    MalformedPrivilegedAccountError,
)
from src.infrastructure.config.sqlite_privileged_account_repository import (
    SQLitePrivilegedAccountRepository,
)
from src.ports.access_dependencies import PrivilegedAccountRepository

PLAINTEXT_CREDENTIAL_MARKER = b"CONFIG-DB-MUST-NOT-CONTAIN-PASSWORD"


def make_repository(
    tmp_path: Path,
) -> tuple[SQLitePrivilegedAccountRepository, Path]:
    database_path = tmp_path / "config.db"
    return SQLitePrivilegedAccountRepository(database_path), database_path


def make_account(
    account_id: str = "account-001",
    *,
    target_id: str = "target-001",
    enabled: bool = True,
) -> PrivilegedAccount:
    return PrivilegedAccount(
        id=account_id,
        target_id=target_id,
        username="root",
        credential_ref=CredentialRef("credential-ref-001"),
        enabled=enabled,
    )


def read_rows(database_path: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, target_id, username, credential_ref, enabled
            FROM privileged_accounts
            ORDER BY id
            """
        ).fetchall()


def update_account_value(
    database_path: Path,
    column: str,
    value: object,
) -> None:
    statements = {
        "username": (
            "UPDATE privileged_accounts SET username = ? WHERE id = ?"
        ),
        "credential_ref": (
            "UPDATE privileged_accounts SET credential_ref = ? WHERE id = ?"
        ),
        "enabled": (
            "UPDATE privileged_accounts SET enabled = ? WHERE id = ?"
        ),
    }
    assert column in statements
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(statements[column], (value, "account-001"))


@pytest.mark.parametrize("enabled", [True, False])
def test_account_and_credential_reference_round_trip(
    tmp_path: Path,
    enabled: bool,
):
    repository, database_path = make_repository(tmp_path)
    account = make_account(enabled=enabled)

    repository.store(account)

    resolved = repository.find_for_target(account.target_id)
    assert resolved == account
    assert resolved.credential_ref == CredentialRef("credential-ref-001")
    assert read_rows(database_path) == [
        (
            "account-001",
            "target-001",
            "root",
            "credential-ref-001",
            int(enabled),
        )
    ]


def test_account_schema_contains_only_credential_reference(tmp_path: Path):
    _, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(privileged_accounts)"
            ).fetchall()
        ]

    assert columns == [
        "id",
        "target_id",
        "username",
        "credential_ref",
        "enabled",
    ]
    assert "password" not in columns
    assert "secret" not in columns
    assert "ciphertext" not in columns


def test_config_database_does_not_contain_plaintext_credential_marker(
    tmp_path: Path,
):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_account())

    assert PLAINTEXT_CREDENTIAL_MARKER not in database_path.read_bytes()


def test_duplicate_account_id_is_rejected_without_overwrite(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_account(enabled=False))
    original = read_rows(database_path)
    replacement = PrivilegedAccount(
        id="account-001",
        target_id="replacement-target",
        username="replacement-user",
        credential_ref=CredentialRef("replacement-ref"),
    )

    with pytest.raises(
        DuplicatePrivilegedAccountError,
        match="privileged account id already exists",
    ):
        repository.store(replacement)

    assert read_rows(database_path) == original


def test_missing_account_returns_none(tmp_path: Path):
    repository, _ = make_repository(tmp_path)

    assert repository.find_for_target("missing-target") is None


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("username", ""),
        ("credential_ref", ""),
        ("enabled", -1),
        ("enabled", 2),
        ("enabled", "yes"),
    ],
)
def test_malformed_account_row_fails_explicitly(
    tmp_path: Path,
    column: str,
    value: object,
):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_account())
    update_account_value(database_path, column, value)

    with pytest.raises(MalformedPrivilegedAccountError):
        repository.find_for_target("target-001")


def test_sql_looking_ids_are_only_values(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    malicious_account_id = "account'; DROP TABLE privileged_accounts; --"
    malicious_target_id = "target' OR 1=1 --"
    account = make_account(
        malicious_account_id,
        target_id=malicious_target_id,
    )
    repository.store(account)
    repository.store(make_account("ordinary-account", target_id="ordinary"))

    assert repository.find_for_target(malicious_target_id) == account
    assert repository.find_for_target("' OR 1=1 --") is None
    assert len(read_rows(database_path)) == 2


def test_multiple_accounts_for_target_fail_as_ambiguous(tmp_path: Path):
    repository, _ = make_repository(tmp_path)
    repository.store(make_account("account-001"))
    repository.store(make_account("account-002"))

    with pytest.raises(
        AmbiguousPrivilegedAccountError,
        match="ambiguous privileged account configuration",
    ):
        repository.find_for_target("target-001")


def test_account_storage_failure_is_explicit(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE privileged_accounts")

    with pytest.raises(
        ConfigStorageError,
        match="privileged account could not be loaded",
    ):
        repository.find_for_target("target-001")


def test_sqlite_account_repository_satisfies_port(tmp_path: Path):
    repository, _ = make_repository(tmp_path)
    account_repository: PrivilegedAccountRepository = repository

    assert account_repository.find_for_target("target-001") is None
