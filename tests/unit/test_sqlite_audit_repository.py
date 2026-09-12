from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
import inspect
from pathlib import Path
import sqlite3

import pytest

from src.application.access_service import AccessService
from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.session import SessionStatus
from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.audit.errors import (
    AuditStorageError,
    DuplicateAuditEventError,
)
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.ports.access_dependencies import AuditRepository
from src.ports.session_broker import BrokerCredential
from tests.fakes.access_dependencies import (
    FakeBrokeredSession,
    FakeIdGenerator,
    FakePrivilegedAccountRepository,
    FakeSessionBroker,
    FakeTargetRepository,
    FakeTerminalIO,
    FakeVault,
    FixedClock,
)
from tests.fakes.policy_repository import FakePolicyRepository


CREDENTIAL_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-CREDENTIAL-MARKER"
TARGET_PASSWORD_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-TARGET-PASSWORD"
PAM_PASSWORD_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-PAM-PASSWORD"
MASTER_KEY_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-MASTER-KEY-MARKER"
TERMINAL_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-TERMINAL-MARKER"
TRANSCRIPT_MARKER = b"AUDIT-DB-MUST-NOT-CONTAIN-SSH-TRANSCRIPT"


def make_event(**changes: object) -> AuditEvent:
    event = AuditEvent(
        id="event-001",
        timestamp=datetime(2026, 9, 12, 10, 30, tzinfo=UTC),
        event_type=AuditEventType.SESSION_ACTIVE,
        actor_user_id="user-001",
        target_id="target-001",
        session_id="session-001",
        result="active",
        reason_code=None,
    )
    return replace(event, **changes)


def read_rows(database_path: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT
                id,
                timestamp,
                event_type,
                actor_user_id,
                target_id,
                session_id,
                result,
                reason_code
            FROM audit_events
            ORDER BY rowid
            """
        ).fetchall()


def test_valid_audit_event_is_appended_with_exact_schema(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)

    repository.append(make_event())

    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(audit_events)"
            ).fetchall()
        ]
    assert columns == [
        "id",
        "timestamp",
        "event_type",
        "actor_user_id",
        "target_id",
        "session_id",
        "result",
        "reason_code",
    ]
    assert read_rows(database_path) == [
        (
            "event-001",
            "2026-09-12T10:30:00.000000Z",
            "session_active",
            "user-001",
            "target-001",
            "session-001",
            "active",
            None,
        )
    ]


def test_timestamp_is_normalized_to_deterministic_utc_text(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    local_timestamp = datetime(
        2026,
        9,
        12,
        13,
        30,
        15,
        123456,
        tzinfo=timezone(timedelta(hours=3)),
    )

    repository.append(make_event(timestamp=local_timestamp))

    assert read_rows(database_path)[0][1] == (
        "2026-09-12T10:30:15.123456Z"
    )


def test_nullable_fields_are_persisted_as_sql_null(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)

    repository.append(
        make_event(
            event_type=AuditEventType.ACCESS_DENIED,
            session_id=None,
            result="denied",
            reason_code=None,
        )
    )

    row = read_rows(database_path)[0]
    assert row[5] is None
    assert row[7] is None


def test_multiple_events_append_without_overwriting(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    first = make_event()
    second = make_event(
        id="event-002",
        event_type=AuditEventType.SESSION_CLOSED,
        result="closed",
        reason_code="relay_completed",
    )

    repository.append(first)
    repository.append(second)

    rows = read_rows(database_path)
    assert [row[0] for row in rows] == ["event-001", "event-002"]
    assert rows[0][6] == "active"
    assert rows[1][6:] == ("closed", "relay_completed")


def test_duplicate_event_id_is_rejected_and_original_is_unchanged(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    repository.append(make_event())
    original_row = read_rows(database_path)[0]

    with pytest.raises(
        DuplicateAuditEventError,
        match="audit event id already exists",
    ):
        repository.append(make_event(result="replacement-attempt"))

    assert read_rows(database_path) == [original_row]


def test_repository_contract_and_implementation_are_append_only(
    tmp_path: Path,
):
    repository = SQLiteAuditRepository(tmp_path / "audit.db")
    repository_port: AuditRepository = repository
    source = inspect.getsource(SQLiteAuditRepository).upper()

    assert "append" in AuditRepository.__dict__
    assert repository_port.append == repository.append
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
    assert "INSERT OR REPLACE" not in source
    assert "UPDATE AUDIT_EVENTS" not in source
    assert "DELETE FROM AUDIT_EVENTS" not in source


def test_opaque_credential_cannot_be_serialized_or_leaked_in_error(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    credential = BrokerCredential(CREDENTIAL_MARKER)
    event = make_event(result=credential)

    with pytest.raises(AuditStorageError) as raised:
        repository.append(event)

    assert CREDENTIAL_MARKER.decode() not in str(raised.value)
    assert CREDENTIAL_MARKER not in database_path.read_bytes()
    assert read_rows(database_path) == []


def test_invalid_database_path_fails_explicitly(tmp_path: Path):
    database_path = tmp_path / "missing-directory" / "audit.db"

    with pytest.raises(
        AuditStorageError,
        match="audit database could not be initialized",
    ):
        SQLiteAuditRepository(database_path)


def test_broken_database_operation_fails_cleanly(tmp_path: Path):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE audit_events")

    with pytest.raises(
        AuditStorageError,
        match="audit event could not be persisted",
    ):
        repository.append(make_event())


def make_policy(effect: AccessEffect) -> AccessPolicy:
    return AccessPolicy(
        id=f"policy-{effect.value}",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=effect,
    )


def make_request() -> AccessRequest:
    return AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 12, 10, tzinfo=UTC),
    )


def make_access_service(
    repository: SQLiteAuditRepository,
    policies: list[AccessPolicy],
    *,
    broker_open_error: Exception | None = None,
) -> tuple[
    AccessService,
    FakeVault,
    FakeSessionBroker,
    FakeBrokeredSession,
    FakeTerminalIO,
]:
    target = Target(
        id="target-001",
        name="production-server",
        host="server.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:abc123"),
    )
    account = PrivilegedAccount(
        id="account-001",
        target_id=target.id,
        username="root",
        credential_ref=CredentialRef("credential-001"),
    )
    vault = FakeVault(BrokerCredential(CREDENTIAL_MARKER))
    brokered_session = FakeBrokeredSession()
    broker = FakeSessionBroker(
        brokered_session,
        open_error=broker_open_error,
    )
    terminal_io = FakeTerminalIO()
    service = AccessService(
        policy_evaluator=PolicyEvaluator(FakePolicyRepository(policies)),
        target_repository=FakeTargetRepository([target]),
        account_repository=FakePrivilegedAccountRepository([account]),
        vault=vault,
        session_broker=broker,
        audit_repository=repository,
        clock=FixedClock(datetime(2026, 9, 12, 10, 5, tzinfo=UTC)),
        id_generator=FakeIdGenerator(),
        max_session_duration=timedelta(minutes=30),
    )
    return service, vault, broker, brokered_session, terminal_io


def test_access_service_allow_flow_persists_complete_lifecycle(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    service, vault, broker, brokered_session, terminal_io = (
        make_access_service(
            repository,
            [make_policy(AccessEffect.ALLOW)],
        )
    )

    result = service.handle(make_request(), terminal_io)

    assert result.session is not None
    assert result.session.status is SessionStatus.CLOSED
    assert len(vault.calls) == 1
    assert len(broker.calls) == 1
    assert len(brokered_session.relay_calls) == 1
    assert [row[2] for row in read_rows(database_path)] == [
        "access_allowed",
        "session_opening",
        "session_active",
        "session_closed",
    ]


def test_access_service_deny_persists_event_without_vault_or_broker(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    service, vault, broker, brokered_session, terminal_io = (
        make_access_service(repository, [])
    )

    result = service.handle(make_request(), terminal_io)

    assert result.session is None
    assert vault.calls == []
    assert broker.calls == []
    assert brokered_session.relay_calls == []
    assert [row[2] for row in read_rows(database_path)] == [
        "access_denied"
    ]


def test_access_service_broker_failure_persists_session_failed(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    service, _, _, brokered_session, terminal_io = make_access_service(
        repository,
        [make_policy(AccessEffect.ALLOW)],
        broker_open_error=RuntimeError("controlled broker failure"),
    )

    result = service.handle(make_request(), terminal_io)

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert brokered_session.relay_calls == []
    assert [row[2] for row in read_rows(database_path)] == [
        "access_allowed",
        "session_opening",
        "session_failed",
    ]


def test_access_flow_does_not_persist_secret_or_terminal_markers(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    service, vault, _, _, terminal_io = make_access_service(
        repository,
        [make_policy(AccessEffect.ALLOW)],
    )
    vault.target_password_marker = TARGET_PASSWORD_MARKER
    vault.pam_password_marker = PAM_PASSWORD_MARKER
    vault.master_key_marker = MASTER_KEY_MARKER
    terminal_io.terminal_content_marker = TERMINAL_MARKER
    terminal_io.transcript_marker = TRANSCRIPT_MARKER
    service.handle(make_request(), terminal_io)

    database_bytes = database_path.read_bytes()
    forbidden_markers = (
        CREDENTIAL_MARKER,
        TARGET_PASSWORD_MARKER,
        PAM_PASSWORD_MARKER,
        MASTER_KEY_MARKER,
        TERMINAL_MARKER,
        TRANSCRIPT_MARKER,
    )
    assert all(marker not in database_bytes for marker in forbidden_markers)


def test_access_service_does_not_swallow_audit_persistence_failure(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    repository = SQLiteAuditRepository(database_path)
    service, vault, broker, _, terminal_io = make_access_service(
        repository,
        [],
    )
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE audit_events")

    with pytest.raises(AuditStorageError):
        service.handle(make_request(), terminal_io)

    assert vault.calls == []
    assert broker.calls == []
