from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
import hashlib
import hmac
import inspect
from pathlib import Path
import secrets
import sqlite3

import pytest

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
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.security.file_key_provider import FileKeyProvider


class StaticKeyProvider:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_key(self) -> bytes:
        return self.key


def make_repository(
    database_path: Path,
    key: bytes | None = None,
) -> tuple[SQLiteAuditRepository, bytes]:
    integrity_key = secrets.token_bytes(32) if key is None else key
    return (
        SQLiteAuditRepository(
            database_path,
            StaticKeyProvider(integrity_key),
        ),
        integrity_key,
    )


def make_event(**changes: object) -> AuditEvent:
    event = AuditEvent(
        id="event-001",
        timestamp=datetime(2026, 9, 12, 10, 30, tzinfo=UTC),
        event_type=AuditEventType.ACCESS_ALLOWED,
        actor_user_id="user-001",
        target_id="target-001",
        session_id="session-001",
        result="allowed",
        reason_code="policy-allow",
    )
    return replace(event, **changes)


def append_events(
    repository: SQLiteAuditRepository,
    count: int,
) -> None:
    for number in range(1, count + 1):
        repository.append(
            make_event(
                id=f"event-{number:03d}",
                timestamp=datetime(
                    2026,
                    9,
                    12,
                    10,
                    30,
                    number,
                    tzinfo=UTC,
                ),
            )
        )


def read_chain_metadata(
    database_path: Path,
) -> list[tuple[int, bytes, bytes]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT sequence_no, previous_mac, event_mac
            FROM audit_events
            ORDER BY sequence_no
            """
        ).fetchall()


def update_audit_field(
    database_path: Path,
    field_name: str,
    value: object,
    sequence_no: int,
) -> None:
    statements = {
        "id": "UPDATE audit_events SET id = ? WHERE sequence_no = ?",
        "actor_user_id": (
            "UPDATE audit_events SET actor_user_id = ? "
            "WHERE sequence_no = ?"
        ),
        "target_id": (
            "UPDATE audit_events SET target_id = ? WHERE sequence_no = ?"
        ),
        "session_id": (
            "UPDATE audit_events SET session_id = ? WHERE sequence_no = ?"
        ),
        "result": (
            "UPDATE audit_events SET result = ? WHERE sequence_no = ?"
        ),
        "reason_code": (
            "UPDATE audit_events SET reason_code = ? WHERE sequence_no = ?"
        ),
        "timestamp": (
            "UPDATE audit_events SET timestamp = ? WHERE sequence_no = ?"
        ),
        "event_type": (
            "UPDATE audit_events SET event_type = ? WHERE sequence_no = ?"
        ),
        "previous_mac": (
            "UPDATE audit_events SET previous_mac = ? WHERE sequence_no = ?"
        ),
        "event_mac": (
            "UPDATE audit_events SET event_mac = ? WHERE sequence_no = ?"
        ),
    }
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                statements[field_name],
                (value, sequence_no),
            )


def canonical_for_event(event: AuditEvent, sequence_no: int = 1) -> bytes:
    serialized = SQLiteAuditRepository._serialize(event)
    return canonical_event_bytes(sequence_no, *serialized)


def test_empty_database_verifies_successfully(tmp_path: Path):
    repository, _ = make_repository(tmp_path / "audit.db")

    assert repository.verify_integrity() is None


def test_first_event_uses_sequence_one_and_zero_genesis(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, key = make_repository(database_path)
    event = make_event()

    repository.append(event)
    repository.verify_integrity()

    sequence_no, previous_mac, event_mac = read_chain_metadata(
        database_path
    )[0]
    canonical = canonical_for_event(event)
    expected_mac = hmac.new(
        key,
        canonical + GENESIS_MAC,
        hashlib.sha256,
    ).digest()
    assert sequence_no == 1
    assert previous_mac == b"\x00" * 32
    assert previous_mac == GENESIS_MAC
    assert event_mac == expected_mac
    assert len(event_mac) == hashlib.sha256().digest_size


def test_multiple_events_form_contiguous_valid_chain(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    append_events(repository, 3)

    repository.verify_integrity()

    rows = read_chain_metadata(database_path)
    assert [row[0] for row in rows] == [1, 2, 3]
    assert rows[1][1] == rows[0][2]
    assert rows[2][1] == rows[1][2]
    assert all(len(row[1]) == 32 and len(row[2]) == 32 for row in rows)


def test_duplicate_append_rolls_back_without_consuming_sequence(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    repository.append(make_event())

    with pytest.raises(DuplicateAuditEventError):
        repository.append(make_event(result="duplicate"))

    repository.append(make_event(id="event-002"))
    assert [row[0] for row in read_chain_metadata(database_path)] == [1, 2]
    repository.verify_integrity()


@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    [
        ("id", "attacker-event"),
        ("actor_user_id", "attacker-user"),
        ("target_id", "attacker-target"),
        ("session_id", "attacker-session"),
        ("result", "tampered-result"),
        ("reason_code", "tampered-reason"),
        ("timestamp", "2040-01-01T00:00:00.000000Z"),
        ("event_type", "tampered_event_type"),
        ("previous_mac", b"\x01" * 32),
        ("event_mac", b"\x02" * 32),
    ],
)
def test_direct_field_tampering_is_detected(
    tmp_path: Path,
    field_name: str,
    tampered_value: object,
):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    append_events(repository, 2)
    update_audit_field(database_path, field_name, tampered_value, 1)

    with pytest.raises(
        AuditIntegrityError,
        match="audit chain integrity verification failed",
    ):
        repository.verify_integrity()


def test_deleting_middle_row_is_detected(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    append_events(repository, 3)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "DELETE FROM audit_events WHERE sequence_no = ?",
                (2,),
            )

    with pytest.raises(AuditIntegrityError):
        repository.verify_integrity()


def test_forged_row_with_invalid_mac_is_detected(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    repository.append(make_event())
    previous_mac = read_chain_metadata(database_path)[0][2]
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
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
                    2,
                    "forged-event",
                    "2026-09-12T10:31:00.000000Z",
                    "access_denied",
                    "attacker",
                    "target-001",
                    None,
                    "denied",
                    "forged",
                    previous_mac,
                    secrets.token_bytes(32),
                ),
            )

    with pytest.raises(AuditIntegrityError):
        repository.verify_integrity()


def test_reordered_rows_are_detected_even_with_contiguous_sequences(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    append_events(repository, 2)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "UPDATE audit_events SET sequence_no = 99 "
                "WHERE sequence_no = 1"
            )
            connection.execute(
                "UPDATE audit_events SET sequence_no = 1 "
                "WHERE sequence_no = 2"
            )
            connection.execute(
                "UPDATE audit_events SET sequence_no = 2 "
                "WHERE sequence_no = 99"
            )

    with pytest.raises(AuditIntegrityError):
        repository.verify_integrity()


def test_verifier_rejects_duplicate_sequence_numbers(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, key = make_repository(database_path)
    append_events(repository, 2)
    with closing(sqlite3.connect(database_path)) as connection:
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
        ).fetchall()
    duplicate_sequence_row = (rows[0][0], *rows[1][1:])

    with pytest.raises(AuditIntegrityError):
        repository._verify_rows(
            [rows[0], duplicate_sequence_row],
            key,
        )


def test_wrong_integrity_key_is_rejected(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, key = make_repository(database_path)
    repository.append(make_event())
    wrong_key = secrets.token_bytes(32)
    assert wrong_key != key
    wrong_key_repository = SQLiteAuditRepository(
        database_path,
        StaticKeyProvider(wrong_key),
    )

    with pytest.raises(AuditIntegrityError) as raised:
        wrong_key_repository.verify_integrity()

    assert key.hex() not in str(raised.value)
    assert wrong_key.hex() not in str(raised.value)


def test_valid_suffix_truncation_is_not_detectable_without_external_anchor(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    append_events(repository, 3)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "DELETE FROM audit_events WHERE sequence_no = ?",
                (3,),
            )

    assert repository.verify_integrity() is None


def test_equivalent_values_have_identical_canonical_bytes():
    event = make_event()

    assert canonical_for_event(event) == canonical_for_event(replace(event))


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    [
        ("sequence_no", 2),
        ("event_id", "event-002"),
        ("timestamp", "2026-09-12T10:30:01.000000Z"),
        ("event_type", "access_denied"),
        ("actor_user_id", "user-002"),
        ("target_id", "target-002"),
        ("session_id", None),
        ("result", "denied"),
        ("reason_code", None),
    ],
)
def test_changing_authenticated_field_changes_canonical_bytes(
    field_name: str,
    changed_value: object,
):
    values = {
        "sequence_no": 1,
        "event_id": "event-001",
        "timestamp": "2026-09-12T10:30:00.000000Z",
        "event_type": "access_allowed",
        "actor_user_id": "user-001",
        "target_id": "target-001",
        "session_id": "session-001",
        "result": "allowed",
        "reason_code": "policy-allow",
    }
    original = canonical_event_bytes(**values)
    values[field_name] = changed_value

    assert canonical_event_bytes(**values) != original


def test_none_and_unicode_are_canonicalized_deterministically():
    values = {
        "sequence_no": 1,
        "event_id": "olay-çığ-001",
        "timestamp": "2026-09-12T10:30:00.000000Z",
        "event_type": "access_denied",
        "actor_user_id": "kullanıcı-ş",
        "target_id": "hedef-ö",
        "session_id": None,
        "result": "reddedildi",
        "reason_code": None,
    }

    first = canonical_event_bytes(**values)
    second = canonical_event_bytes(**values)

    assert first == second
    assert "kullanıcı-ş".encode() in first
    assert first.count(b"null") == 2


def test_equivalent_instants_have_identical_canonical_bytes():
    utc_event = make_event()
    local_event = replace(
        utc_event,
        timestamp=datetime(
            2026,
            9,
            12,
            13,
            30,
            tzinfo=timezone(timedelta(hours=3)),
        ),
    )

    assert canonical_for_event(utc_event) == canonical_for_event(local_event)


def test_file_key_provider_can_supply_dedicated_integrity_key(
    tmp_path: Path,
):
    key = secrets.token_bytes(32)
    key_file = tmp_path / "audit-integrity.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    repository = SQLiteAuditRepository(
        tmp_path / "audit.db",
        FileKeyProvider(key_file),
    )

    repository.append(make_event())

    repository.verify_integrity()


def test_invalid_integrity_key_length_fails_without_key_disclosure(
    tmp_path: Path,
):
    invalid_key = secrets.token_bytes(31)

    with pytest.raises(AuditStorageError) as raised:
        SQLiteAuditRepository(
            tmp_path / "audit.db",
            StaticKeyProvider(invalid_key),
        )

    assert invalid_key.hex() not in str(raised.value)
    assert repr(invalid_key) not in str(raised.value)


def test_integrity_and_vault_keys_are_not_persisted_or_revealed(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    audit_integrity_key = secrets.token_bytes(32)
    vault_master_key = secrets.token_bytes(32)
    assert audit_integrity_key != vault_master_key
    repository, _ = make_repository(database_path, audit_integrity_key)
    repository.append(make_event())

    database_bytes = database_path.read_bytes()
    representation = repr(repository)
    assert audit_integrity_key not in database_bytes
    assert vault_master_key not in database_bytes
    assert audit_integrity_key.hex() not in representation
    assert repr(audit_integrity_key) not in representation


def test_phase_7a_schema_is_rejected_instead_of_silently_used(
    tmp_path: Path,
):
    database_path = tmp_path / "old-audit.db"
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE audit_events (
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

    with pytest.raises(
        UnsupportedAuditSchemaError,
        match="recreate the audit database",
    ):
        SQLiteAuditRepository(
            database_path,
            StaticKeyProvider(secrets.token_bytes(32)),
        )


def test_schema_version_and_security_primitives_are_explicit(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository, _ = make_repository(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        schema_version = connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
    repository_source = inspect.getsource(SQLiteAuditRepository)
    integrity_source = inspect.getsource(calculate_event_mac)
    comparison_source = inspect.getsource(macs_match)

    assert schema_version == 2
    assert 'connection.execute("BEGIN IMMEDIATE")' in repository_source
    assert "INSERT OR REPLACE" not in repository_source.upper()
    assert "hmac.new" in integrity_source
    assert "hashlib.sha256" in integrity_source
    assert "hmac.compare_digest" in comparison_source
