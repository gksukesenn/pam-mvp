import sqlite3
from collections.abc import Iterable
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from src.domain.audit import AuditEvent, AuditEventType
from src.infrastructure.audit.errors import (
    AuditIntegrityError,
    AuditStorageError,
    DuplicateAuditEventError,
    UnsupportedAuditSchemaError,
)
from src.infrastructure.audit.integrity import (
    GENESIS_MAC,
    calculate_event_mac,
    canonical_event_bytes,
    macs_match,
)
from src.infrastructure.sqlite_security import (
    DatabasePermissionError,
    ensure_owner_only_database_file,
)
from src.ports.security import KeyProvider

SCHEMA_VERSION = 2
MAC_SIZE = 32
SCHEMA_COLUMNS = (
    "sequence_no",
    "id",
    "timestamp",
    "event_type",
    "actor_user_id",
    "target_id",
    "session_id",
    "result",
    "reason_code",
    "previous_mac",
    "event_mac",
)


class SQLiteAuditRepository:
    """Append-only, HMAC-chained SQLite storage for audit events.

    A valid suffix can be removed without detection unless the chain head is
    anchored in trusted external state. External anchoring is intentionally
    deferred. The configured integrity-key provider must be dedicated to audit
    integrity and must not provide the Vault master key.
    """

    __slots__ = ("_database_path", "_key_provider")

    def __init__(
        self,
        database_path: Path,
        integrity_key_provider: KeyProvider,
    ) -> None:
        self._database_path = database_path
        self._key_provider = integrity_key_provider
        self._load_key()
        self._initialize_schema()

    def append(self, event: AuditEvent) -> None:
        serialized_event = self._serialize(event)
        key = self._load_key()

        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    head = connection.execute(
                        """
                        SELECT sequence_no, event_mac
                        FROM audit_events
                        ORDER BY sequence_no DESC
                        LIMIT 1
                        """
                    ).fetchone()
                    sequence_no, previous_mac = self._next_chain_link(head)
                    canonical = canonical_event_bytes(
                        sequence_no,
                        *serialized_event,
                    )
                    event_mac = calculate_event_mac(
                        key,
                        canonical,
                        previous_mac,
                    )
                    connection.execute(
                        """
                        INSERT INTO audit_events (
                            sequence_no,
                            id,
                            timestamp,
                            event_type,
                            actor_user_id,
                            target_id,
                            session_id,
                            result,
                            reason_code,
                            previous_mac,
                            event_mac
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sequence_no,
                            *serialized_event,
                            previous_mac,
                            event_mac,
                        ),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except sqlite3.IntegrityError as error:
            raise DuplicateAuditEventError(
                "audit event id already exists"
            ) from error
        except AuditStorageError:
            raise
        except sqlite3.Error as error:
            raise AuditStorageError(
                "audit event could not be persisted"
            ) from error
        except Exception as error:
            raise AuditStorageError(
                "audit event could not be chained"
            ) from error

    def verify_integrity(self) -> None:
        key = self._load_key()
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                rows = connection.execute(
                    """
                    SELECT
                        sequence_no,
                        id,
                        timestamp,
                        event_type,
                        actor_user_id,
                        target_id,
                        session_id,
                        result,
                        reason_code,
                        previous_mac,
                        event_mac
                    FROM audit_events
                    ORDER BY sequence_no
                    """
                )
                self._verify_rows(rows, key)
        except AuditIntegrityError:
            raise
        except sqlite3.Error as error:
            raise AuditStorageError(
                "audit events could not be verified"
            ) from error
        except Exception as error:
            raise AuditIntegrityError(
                "audit chain integrity verification failed"
            ) from error

    @staticmethod
    def _verify_rows(
        rows: Iterable[tuple[object, ...]],
        key: bytes,
    ) -> None:
        expected_sequence = 1
        expected_previous_mac = GENESIS_MAC
        for row in rows:
            SQLiteAuditRepository._validate_stored_row(row)
            (
                sequence_no,
                event_id,
                timestamp,
                event_type,
                actor_user_id,
                target_id,
                session_id,
                result,
                reason_code,
                previous_mac,
                event_mac,
            ) = row
            if sequence_no != expected_sequence or not macs_match(
                previous_mac,
                expected_previous_mac,
            ):
                raise AuditIntegrityError(
                    "audit chain integrity verification failed"
                )

            canonical = canonical_event_bytes(
                sequence_no,
                event_id,
                timestamp,
                event_type,
                actor_user_id,
                target_id,
                session_id,
                result,
                reason_code,
            )
            expected_event_mac = calculate_event_mac(
                key,
                canonical,
                previous_mac,
            )
            if not macs_match(event_mac, expected_event_mac):
                raise AuditIntegrityError(
                    "audit chain integrity verification failed"
                )

            expected_sequence += 1
            expected_previous_mac = event_mac

    @staticmethod
    def _validate_stored_row(row: object) -> None:
        if not isinstance(row, tuple) or len(row) != len(SCHEMA_COLUMNS):
            raise AuditIntegrityError(
                "audit chain integrity verification failed"
            )

        required_strings = row[1:6] + (row[7],)
        optional_strings = (row[6], row[8])
        if (
            not isinstance(row[0], int)
            or not all(
                isinstance(value, str) for value in required_strings
            )
            or not all(
                value is None or isinstance(value, str)
                for value in optional_strings
            )
            or not isinstance(row[9], bytes)
            or len(row[9]) != MAC_SIZE
            or not isinstance(row[10], bytes)
            or len(row[10]) != MAC_SIZE
        ):
            raise AuditIntegrityError(
                "audit chain integrity verification failed"
            )

    @staticmethod
    def _next_chain_link(
        head: tuple[object, ...] | None,
    ) -> tuple[int, bytes]:
        if head is None:
            return 1, GENESIS_MAC
        if (
            len(head) != 2
            or not isinstance(head[0], int)
            or head[0] < 1
            or not isinstance(head[1], bytes)
            or len(head[1]) != MAC_SIZE
        ):
            raise AuditStorageError("audit chain head is invalid")
        return head[0] + 1, head[1]

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

    def _load_key(self) -> bytes:
        try:
            key = self._key_provider.get_key()
        except Exception as error:
            raise AuditStorageError(
                "audit integrity key could not be loaded"
            ) from error
        if not isinstance(key, bytes) or len(key) != MAC_SIZE:
            raise AuditStorageError(
                "audit integrity key must be exactly 32 bytes"
            )
        return key

    def _initialize_schema(self) -> None:
        try:
            ensure_owner_only_database_file(self._database_path)
            with closing(sqlite3.connect(self._database_path)) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    version = connection.execute(
                        "PRAGMA user_version"
                    ).fetchone()[0]
                    table_exists = connection.execute(
                        """
                        SELECT 1
                        FROM sqlite_master
                        WHERE type = ? AND name = ?
                        """,
                        ("table", "audit_events"),
                    ).fetchone() is not None

                    if table_exists:
                        self._validate_existing_schema(connection, version)
                    elif version == 0:
                        self._create_schema(connection)
                    else:
                        raise UnsupportedAuditSchemaError(
                            "audit database schema is unsupported; "
                            "recreate the audit database"
                        )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except AuditStorageError:
            raise
        except (DatabasePermissionError, sqlite3.Error) as error:
            raise AuditStorageError(
                "audit database could not be initialized"
            ) from error

    @staticmethod
    def _validate_existing_schema(
        connection: sqlite3.Connection,
        version: int,
    ) -> None:
        columns = tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(audit_events)"
            ).fetchall()
        )
        if version != SCHEMA_VERSION or columns != SCHEMA_COLUMNS:
            raise UnsupportedAuditSchemaError(
                "audit database schema is unsupported; "
                "recreate the audit database"
            )

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE audit_events (
                sequence_no INTEGER NOT NULL UNIQUE,
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_user_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                session_id TEXT,
                result TEXT NOT NULL,
                reason_code TEXT,
                previous_mac BLOB NOT NULL,
                event_mac BLOB NOT NULL
            )
            """
        )
        connection.execute("PRAGMA user_version = 2")
