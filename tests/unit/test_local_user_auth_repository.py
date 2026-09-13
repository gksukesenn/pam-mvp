from contextlib import closing
from pathlib import Path
import sqlite3

import pytest

from src.domain.user import User
from src.infrastructure.auth.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from src.infrastructure.auth.errors import (
    DuplicateUserIdError,
    DuplicateUsernameError,
    MalformedUserAuthError,
    UnsupportedUserAuthSchemaError,
    UserAuthStorageError,
)
from src.infrastructure.auth.sqlite_user_auth_repository import (
    SQLiteUserAuthRepository,
)
from src.ports.authentication import (
    PasswordHasher,
    UserAuthenticationRepository,
)


PASSWORD_MARKER = "PAM-LOGIN-PLAINTEXT-MARKER"


def make_repository(
    tmp_path: Path,
) -> tuple[SQLiteUserAuthRepository, Argon2PasswordHasher, Path]:
    database_path = tmp_path / "auth.db"
    password_hasher = Argon2PasswordHasher()
    return (
        SQLiteUserAuthRepository(database_path, password_hasher),
        password_hasher,
        database_path,
    )


def make_user(
    user_id: str = "user-001",
    username: str = "goksu",
    *,
    is_active: bool = True,
) -> User:
    return User(id=user_id, username=username, is_active=is_active)


def read_rows(database_path: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, username, password_hash, enabled
            FROM pam_users
            ORDER BY id
            """
        ).fetchall()


def test_creation_stores_only_encoded_argon2id_hash(tmp_path: Path):
    repository, password_hasher, database_path = make_repository(tmp_path)

    repository.create_user(make_user(), PASSWORD_MARKER)

    rows = read_rows(database_path)
    assert len(rows) == 1
    user_id, username, encoded_hash, enabled = rows[0]
    assert (user_id, username, enabled) == ("user-001", "goksu", 1)
    assert isinstance(encoded_hash, str)
    assert encoded_hash.startswith("$argon2id$")
    assert PASSWORD_MARKER not in encoded_hash
    assert PASSWORD_MARKER.encode() not in database_path.read_bytes()
    assert password_hasher.verify(PASSWORD_MARKER, encoded_hash) is True
    assert password_hasher.verify("wrong-password", encoded_hash) is False


def test_same_password_uses_distinct_library_generated_salts(tmp_path: Path):
    repository, _, database_path = make_repository(tmp_path)

    repository.create_user(make_user(), PASSWORD_MARKER)
    repository.create_user(
        make_user("user-002", "alice"),
        PASSWORD_MARKER,
    )

    hashes = [row[2] for row in read_rows(database_path)]
    assert hashes[0] != hashes[1]
    assert all(value.startswith("$argon2id$") for value in hashes)


def test_inactive_flag_and_user_fields_round_trip(tmp_path: Path):
    repository, _, _ = make_repository(tmp_path)
    user = make_user(is_active=False)

    repository.create_user(user, PASSWORD_MARKER)
    stored_authentication = repository.find_by_username(user.username)

    assert stored_authentication is not None
    assert stored_authentication.user == user
    assert stored_authentication.user.is_active is False
    assert PASSWORD_MARKER not in repr(stored_authentication)
    assert stored_authentication.password_hash not in repr(stored_authentication)


def test_missing_username_returns_none(tmp_path: Path):
    repository, _, _ = make_repository(tmp_path)

    assert repository.find_by_username("missing") is None


def test_duplicate_user_id_is_rejected_without_overwrite(tmp_path: Path):
    repository, _, database_path = make_repository(tmp_path)
    repository.create_user(make_user(), PASSWORD_MARKER)
    original = read_rows(database_path)

    with pytest.raises(
        DuplicateUserIdError,
        match="PAM user id already exists",
    ):
        repository.create_user(
            make_user(username="different"),
            "replacement-password",
        )

    assert read_rows(database_path) == original


def test_duplicate_username_is_rejected_without_overwrite(tmp_path: Path):
    repository, _, database_path = make_repository(tmp_path)
    repository.create_user(make_user(), PASSWORD_MARKER)
    original = read_rows(database_path)

    with pytest.raises(
        DuplicateUsernameError,
        match="PAM username already exists",
    ):
        repository.create_user(
            make_user("user-002"),
            "replacement-password",
        )

    assert read_rows(database_path) == original


def test_malformed_hash_fails_closed_and_malformed_row_is_explicit(
    tmp_path: Path,
):
    repository, password_hasher, database_path = make_repository(tmp_path)
    assert password_hasher.verify(PASSWORD_MARKER, "not-an-argon2-hash") is False
    repository.create_user(make_user(), PASSWORD_MARKER)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "UPDATE pam_users SET password_hash = ? WHERE id = ?",
                ("malformed", "user-001"),
            )

    with pytest.raises(
        MalformedUserAuthError,
        match="PAM user contains invalid stored values",
    ):
        repository.find_by_username("goksu")


def test_schema_is_exact_and_separate_from_other_material(tmp_path: Path):
    _, _, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(pam_users)"
            ).fetchall()
        ]
        tables = [
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        ]

    assert columns == ["id", "username", "password_hash", "enabled"]
    assert tables == ["pam_users"]


def test_unsupported_existing_schema_fails_explicitly(tmp_path: Path):
    database_path = tmp_path / "auth.db"
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "CREATE TABLE pam_users (id TEXT PRIMARY KEY)"
            )

    with pytest.raises(
        UnsupportedUserAuthSchemaError,
        match="authentication database schema is unsupported",
    ):
        SQLiteUserAuthRepository(database_path, Argon2PasswordHasher())


def test_storage_failure_is_explicit_and_contains_no_password(tmp_path: Path):
    repository, _, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE pam_users")

    with pytest.raises(UserAuthStorageError) as captured:
        repository.create_user(make_user(), PASSWORD_MARKER)

    assert PASSWORD_MARKER not in repr(captured.value)


def test_concrete_components_satisfy_infrastructure_neutral_ports(
    tmp_path: Path,
):
    repository, password_hasher, _ = make_repository(tmp_path)
    repository_port: UserAuthenticationRepository = repository
    hasher_port: PasswordHasher = password_hasher

    assert repository_port.find_by_username("missing") is None
    assert hasher_port.verify("password", "malformed") is False
