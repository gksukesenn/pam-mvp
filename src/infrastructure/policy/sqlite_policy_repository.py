import sqlite3
from collections.abc import Collection
from contextlib import closing
from pathlib import Path

from src.domain.access import AccessAction, AccessEffect, AccessPolicy
from src.infrastructure.policy.errors import (
    DuplicatePolicyError,
    MalformedPolicyError,
    PolicyStorageError,
)
from src.infrastructure.sqlite_security import (
    DatabasePermissionError,
    ensure_owner_only_database_file,
)

SCHEMA_COLUMNS = (
    "id",
    "user_id",
    "target_id",
    "action",
    "effect",
)
SCHEMA_DEFINITION = (
    ("id", "TEXT", 0, None, 1),
    ("user_id", "TEXT", 1, None, 0),
    ("target_id", "TEXT", 1, None, 0),
    ("action", "TEXT", 1, None, 0),
    ("effect", "TEXT", 1, None, 0),
)


class SQLitePolicyRepository:
    """SQLite-backed direct access-policy matching and provisioning."""

    __slots__ = ("_database_path",)

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize_schema()

    def store(self, policy: AccessPolicy) -> None:
        serialized = self._serialize(policy)
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO access_policies (
                            id,
                            user_id,
                            target_id,
                            action,
                            effect
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        serialized,
                    )
        except sqlite3.IntegrityError as error:
            if error.sqlite_errorcode in {
                sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                sqlite3.SQLITE_CONSTRAINT_UNIQUE,
            }:
                raise DuplicatePolicyError(
                    "policy id already exists"
                ) from error
            raise PolicyStorageError("policy could not be stored") from error
        except sqlite3.Error as error:
            raise PolicyStorageError("policy could not be stored") from error

    def find_matching(
        self,
        user_id: str,
        target_id: str,
        action: AccessAction,
    ) -> Collection[AccessPolicy]:
        if not isinstance(action, AccessAction):
            raise PolicyStorageError("unsupported policy query")

        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                rows = connection.execute(
                    """
                    SELECT id, user_id, target_id, action, effect
                    FROM access_policies
                    WHERE user_id = ? AND target_id = ? AND action = ?
                    ORDER BY id
                    """,
                    (user_id, target_id, action.value),
                ).fetchall()
        except sqlite3.Error as error:
            raise PolicyStorageError("policies could not be loaded") from error

        return [self._deserialize(row) for row in rows]

    @staticmethod
    def _serialize(policy: AccessPolicy) -> tuple[str, ...]:
        if (
            not isinstance(policy, AccessPolicy)
            or type(policy.id) is not str
            or type(policy.user_id) is not str
            or type(policy.target_id) is not str
            or not policy.id.strip()
            or not policy.user_id.strip()
            or not policy.target_id.strip()
            or not isinstance(policy.action, AccessAction)
            or not isinstance(policy.effect, AccessEffect)
        ):
            raise PolicyStorageError(
                "policy contains unsupported field values"
            )

        return (
            policy.id,
            policy.user_id,
            policy.target_id,
            policy.action.value,
            policy.effect.value,
        )

    @staticmethod
    def _deserialize(row: object) -> AccessPolicy:
        if (
            not isinstance(row, tuple)
            or len(row) != len(SCHEMA_COLUMNS)
            or not all(type(value) is str for value in row)
        ):
            raise MalformedPolicyError(
                "matching policy contains invalid stored values"
            )

        policy_id, user_id, target_id, action, effect = row
        try:
            return AccessPolicy(
                id=policy_id,
                user_id=user_id,
                target_id=target_id,
                action=AccessAction(action),
                effect=AccessEffect(effect),
            )
        except (TypeError, ValueError) as error:
            raise MalformedPolicyError(
                "matching policy contains invalid stored values"
            ) from error

    def _initialize_schema(self) -> None:
        try:
            ensure_owner_only_database_file(self._database_path)
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS access_policies (
                            id TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL,
                            target_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            effect TEXT NOT NULL
                        )
                        """
                    )
                    definition = tuple(
                        (row[1], row[2].upper(), row[3], row[4], row[5])
                        for row in connection.execute(
                            "PRAGMA table_info(access_policies)"
                        ).fetchall()
                    )
                    if definition != SCHEMA_DEFINITION:
                        raise PolicyStorageError(
                            "policy database schema is unsupported"
                        )
        except PolicyStorageError:
            raise
        except (DatabasePermissionError, sqlite3.Error) as error:
            raise PolicyStorageError(
                "policy database could not be initialized"
            ) from error
