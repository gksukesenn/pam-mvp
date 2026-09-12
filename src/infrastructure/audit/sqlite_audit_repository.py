from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
import sqlite3

from src.domain.audit import AuditEvent, AuditEventType
from src.infrastructure.audit.errors import (
    AuditStorageError,
    DuplicateAuditEventError,
)


class SQLiteAuditRepository:
    """Append-only SQLite storage for structured audit events."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize_schema()

    def append(self, event: AuditEvent) -> None:
        values = self._serialize(event)

        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO audit_events (
                            id,
                            timestamp,
                            event_type,
                            actor_user_id,
                            target_id,
                            session_id,
                            result,
                            reason_code
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        values,
                    )
        except sqlite3.IntegrityError as error:
            raise DuplicateAuditEventError(
                "audit event id already exists"
            ) from error
        except sqlite3.Error as error:
            raise AuditStorageError(
                "audit event could not be persisted"
            ) from error

    @staticmethod
    def _serialize(event: AuditEvent) -> tuple[object, ...]:
        if not isinstance(event, AuditEvent):
            raise AuditStorageError("unsupported audit event")

        required_strings = (
            event.id,
            event.actor_user_id,
            event.target_id,
            event.result,
        )
        optional_strings = (event.session_id, event.reason_code)
        if (
            not all(isinstance(value, str) for value in required_strings)
            or not all(
                value is None or isinstance(value, str)
                for value in optional_strings
            )
            or not isinstance(event.event_type, AuditEventType)
            or not isinstance(event.timestamp, datetime)
        ):
            raise AuditStorageError(
                "audit event contains unsupported field values"
            )

        if (
            event.timestamp.tzinfo is None
            or event.timestamp.utcoffset() is None
        ):
            raise AuditStorageError(
                "audit event contains an invalid timestamp"
            )

        try:
            timestamp = (
                event.timestamp.astimezone(UTC)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
        except (TypeError, ValueError) as error:
            raise AuditStorageError(
                "audit event contains an invalid timestamp"
            ) from error

        return (
            event.id,
            timestamp,
            event.event_type.value,
            event.actor_user_id,
            event.target_id,
            event.session_id,
            event.result,
            event.reason_code,
        )

    def _initialize_schema(self) -> None:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_events (
                            id TEXT PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            actor_user_id TEXT NOT NULL,
                            target_id TEXT NOT NULL,
                            session_id TEXT,
                            result TEXT NOT NULL,
                            reason_code TEXT
                        )
                        """
                    )
        except sqlite3.Error as error:
            raise AuditStorageError(
                "audit database could not be initialized"
            ) from error
