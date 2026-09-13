from contextlib import closing
from pathlib import Path
import sqlite3

from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.infrastructure.config.errors import (
    AmbiguousPrivilegedAccountError,
    ConfigStorageError,
    DuplicatePrivilegedAccountError,
    MalformedPrivilegedAccountError,
)


SCHEMA_DEFINITION = (
    ("id", "TEXT", 0, None, 1),
    ("target_id", "TEXT", 1, None, 0),
    ("username", "TEXT", 1, None, 0),
    ("credential_ref", "TEXT", 1, None, 0),
    ("enabled", "INTEGER", 1, None, 0),
)


class SQLitePrivilegedAccountRepository:
    """Resolve the single configured privileged account for a target.

    The MVP has no account-selection input. More than one account for the same
    target is therefore ambiguous and fails closed instead of selecting one.
    """

    __slots__ = ("_database_path",)

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize_schema()

    def store(self, account: PrivilegedAccount) -> None:
        serialized = self._serialize(account)
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO privileged_accounts (
                            id,
                            target_id,
                            username,
                            credential_ref,
                            enabled
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        serialized,
                    )
        except sqlite3.IntegrityError as error:
            if error.sqlite_errorcode in {
                sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                sqlite3.SQLITE_CONSTRAINT_UNIQUE,
            }:
                raise DuplicatePrivilegedAccountError(
                    "privileged account id already exists"
                ) from error
            raise ConfigStorageError(
                "privileged account could not be stored"
            ) from error
        except sqlite3.Error as error:
            raise ConfigStorageError(
                "privileged account could not be stored"
            ) from error

    def find_for_target(
        self,
        target_id: str,
    ) -> PrivilegedAccount | None:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                rows = connection.execute(
                    """
                    SELECT
                        id,
                        target_id,
                        username,
                        credential_ref,
                        enabled
                    FROM privileged_accounts
                    WHERE target_id = ?
                    ORDER BY id
                    """,
                    (target_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise ConfigStorageError(
                "privileged account could not be loaded"
            ) from error

        if not rows:
            return None
        if len(rows) != 1:
            raise AmbiguousPrivilegedAccountError(
                "target has ambiguous privileged account configuration"
            )
        return self._deserialize(rows[0])

    @staticmethod
    def _serialize(account: PrivilegedAccount) -> tuple[object, ...]:
        if (
            not isinstance(account, PrivilegedAccount)
            or type(account.id) is not str
            or type(account.target_id) is not str
            or type(account.username) is not str
            or not account.id.strip()
            or not account.target_id.strip()
            or not account.username.strip()
            or not isinstance(account.credential_ref, CredentialRef)
            or type(account.credential_ref.id) is not str
            or not account.credential_ref.id.strip()
            or type(account.enabled) is not bool
        ):
            raise ConfigStorageError(
                "privileged account contains unsupported field values"
            )

        return (
            account.id,
            account.target_id,
            account.username,
            account.credential_ref.id,
            int(account.enabled),
        )

    @staticmethod
    def _deserialize(row: object) -> PrivilegedAccount:
        if (
            not isinstance(row, tuple)
            or len(row) != len(SCHEMA_DEFINITION)
            or not all(type(value) is str for value in row[:4])
            or type(row[4]) is not int
            or row[4] not in (0, 1)
        ):
            raise MalformedPrivilegedAccountError(
                "privileged account contains invalid stored values"
            )

        account_id, target_id, username, credential_ref, enabled = row
        try:
            return PrivilegedAccount(
                id=account_id,
                target_id=target_id,
                username=username,
                credential_ref=CredentialRef(credential_ref),
                enabled=bool(enabled),
            )
        except (TypeError, ValueError) as error:
            raise MalformedPrivilegedAccountError(
                "privileged account contains invalid stored values"
            ) from error

    def _initialize_schema(self) -> None:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS privileged_accounts (
                            id TEXT PRIMARY KEY,
                            target_id TEXT NOT NULL,
                            username TEXT NOT NULL,
                            credential_ref TEXT NOT NULL,
                            enabled INTEGER NOT NULL
                        )
                        """
                    )
                    definition = tuple(
                        (row[1], row[2].upper(), row[3], row[4], row[5])
                        for row in connection.execute(
                            "PRAGMA table_info(privileged_accounts)"
                        ).fetchall()
                    )
                    if definition != SCHEMA_DEFINITION:
                        raise ConfigStorageError(
                            "privileged account database schema is unsupported"
                        )
        except ConfigStorageError:
            raise
        except sqlite3.Error as error:
            raise ConfigStorageError(
                "privileged account database could not be initialized"
            ) from error
