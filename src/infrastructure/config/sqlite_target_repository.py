from contextlib import closing
from pathlib import Path
import sqlite3

from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.config.errors import (
    ConfigStorageError,
    DuplicateTargetError,
    MalformedTargetError,
)


SCHEMA_DEFINITION = (
    ("id", "TEXT", 0, None, 1),
    ("name", "TEXT", 1, None, 0),
    ("host", "TEXT", 1, None, 0),
    ("port", "INTEGER", 1, None, 0),
    ("expected_host_key", "TEXT", 1, None, 0),
    ("enabled", "INTEGER", 1, None, 0),
)


class SQLiteTargetRepository:
    """SQLite-backed target lookup and infrastructure provisioning."""

    __slots__ = ("_database_path",)

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize_schema()

    def store(self, target: Target) -> None:
        serialized = self._serialize(target)
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO targets (
                            id,
                            name,
                            host,
                            port,
                            expected_host_key,
                            enabled
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        serialized,
                    )
        except sqlite3.IntegrityError as error:
            if error.sqlite_errorcode in {
                sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                sqlite3.SQLITE_CONSTRAINT_UNIQUE,
            }:
                raise DuplicateTargetError(
                    "target id already exists"
                ) from error
            raise ConfigStorageError("target could not be stored") from error
        except sqlite3.Error as error:
            raise ConfigStorageError("target could not be stored") from error

    def get(self, target_id: str) -> Target | None:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                row = connection.execute(
                    """
                    SELECT
                        id,
                        name,
                        host,
                        port,
                        expected_host_key,
                        enabled
                    FROM targets
                    WHERE id = ?
                    """,
                    (target_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise ConfigStorageError("target could not be loaded") from error

        if row is None:
            return None
        return self._deserialize(row)

    @staticmethod
    def _serialize(target: Target) -> tuple[object, ...]:
        if (
            not isinstance(target, Target)
            or type(target.id) is not str
            or type(target.name) is not str
            or type(target.host) is not str
            or not target.id.strip()
            or not target.name.strip()
            or not target.host.strip()
            or type(target.port) is not int
            or not 1 <= target.port <= 65535
            or not isinstance(target.expected_host_key, HostKeyFingerprint)
            or type(target.expected_host_key.value) is not str
            or not target.expected_host_key.value.startswith("SHA256:")
            or type(target.enabled) is not bool
        ):
            raise ConfigStorageError(
                "target contains unsupported field values"
            )

        return (
            target.id,
            target.name,
            target.host,
            target.port,
            target.expected_host_key.value,
            int(target.enabled),
        )

    @staticmethod
    def _deserialize(row: object) -> Target:
        if (
            not isinstance(row, tuple)
            or len(row) != len(SCHEMA_DEFINITION)
            or not all(type(value) is str for value in row[:3])
            or type(row[3]) is not int
            or type(row[4]) is not str
            or type(row[5]) is not int
            or row[5] not in (0, 1)
        ):
            raise MalformedTargetError(
                "target contains invalid stored values"
            )

        target_id, name, host, port, fingerprint, enabled = row
        try:
            return Target(
                id=target_id,
                name=name,
                host=host,
                port=port,
                expected_host_key=HostKeyFingerprint(fingerprint),
                enabled=bool(enabled),
            )
        except (TypeError, ValueError) as error:
            raise MalformedTargetError(
                "target contains invalid stored values"
            ) from error

    def _initialize_schema(self) -> None:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS targets (
                            id TEXT PRIMARY KEY,
                            name TEXT NOT NULL,
                            host TEXT NOT NULL,
                            port INTEGER NOT NULL,
                            expected_host_key TEXT NOT NULL,
                            enabled INTEGER NOT NULL
                        )
                        """
                    )
                    definition = tuple(
                        (row[1], row[2].upper(), row[3], row[4], row[5])
                        for row in connection.execute(
                            "PRAGMA table_info(targets)"
                        ).fetchall()
                    )
                    if definition != SCHEMA_DEFINITION:
                        raise ConfigStorageError(
                            "target database schema is unsupported"
                        )
        except ConfigStorageError:
            raise
        except sqlite3.Error as error:
            raise ConfigStorageError(
                "target database could not be initialized"
            ) from error
