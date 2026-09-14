from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta

import pytest

import src.application.access_service as access_service_module
from src.application.access_service import AccessResult, AccessService
from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessDecision,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.authentication import AuthenticatedPrincipal
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.session import Session, SessionStatus
from src.domain.target import HostKeyFingerprint, Target
from src.ports.session_broker import BrokerCredential, RelayOutcome
from tests.fakes.access_dependencies import (
    FakeAuditRepository,
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

INTERNAL_CREDENTIAL_BYTES = b"vault-internal-password"
INTERNAL_CREDENTIAL = BrokerCredential(INTERNAL_CREDENTIAL_BYTES)
MAX_SESSION_DURATION = timedelta(minutes=30)
PRINCIPAL = AuthenticatedPrincipal(user_id="user-001", username="goksu")


class SequenceClock:
    def __init__(self, values: list[datetime]) -> None:
        self._values = iter(values)
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return next(self._values)


@dataclass
class Harness:
    service: AccessService
    policy_repository: FakePolicyRepository
    target_repository: FakeTargetRepository
    account_repository: FakePrivilegedAccountRepository
    vault: FakeVault
    broker: FakeSessionBroker
    brokered_session: FakeBrokeredSession
    terminal_io: FakeTerminalIO
    audit_repository: FakeAuditRepository
    id_generator: FakeIdGenerator
    call_log: list[str]


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


def make_target(*, enabled: bool = True) -> Target:
    return Target(
        id="target-001",
        name="production-server",
        host="server.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:abc123"),
        enabled=enabled,
    )


def make_account(*, enabled: bool = True) -> PrivilegedAccount:
    return PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=CredentialRef("credential-001"),
        enabled=enabled,
    )


def make_harness(
    policies: list[AccessPolicy],
    *,
    targets: list[Target] | None = None,
    accounts: list[PrivilegedAccount] | None = None,
    credential: BrokerCredential | None = INTERNAL_CREDENTIAL,
    broker_open_error: Exception | None = None,
    relay_error: Exception | None = None,
    close_error: Exception | None = None,
    audit_repository: FakeAuditRepository | None = None,
    relay_outcome: RelayOutcome = RelayOutcome.COMPLETED,
    max_session_duration: timedelta = MAX_SESSION_DURATION,
) -> Harness:
    call_log: list[str] = []
    policy_repository = FakePolicyRepository(policies, call_log)
    target_repository = FakeTargetRepository(
        [make_target()] if targets is None else targets,
        call_log,
    )
    account_repository = FakePrivilegedAccountRepository(
        [make_account()] if accounts is None else accounts,
        call_log,
    )
    vault = FakeVault(credential, call_log)
    brokered_session = FakeBrokeredSession(
        call_log=call_log,
        relay_error=relay_error,
        close_error=close_error,
        relay_outcome=relay_outcome,
    )
    broker = FakeSessionBroker(
        brokered_session,
        call_log,
        open_error=broker_open_error,
    )
    terminal_io = FakeTerminalIO()
    if audit_repository is None:
        audit_repository = FakeAuditRepository(call_log)
    else:
        audit_repository.call_log = call_log
    id_generator = FakeIdGenerator()
    service = AccessService(
        policy_evaluator=PolicyEvaluator(policy_repository),
        target_repository=target_repository,
        account_repository=account_repository,
        vault=vault,
        session_broker=broker,
        audit_repository=audit_repository,
        clock=FixedClock(datetime(2026, 9, 12, 10, 5, tzinfo=UTC)),
        id_generator=id_generator,
        max_session_duration=max_session_duration,
    )
    return Harness(
        service=service,
        policy_repository=policy_repository,
        target_repository=target_repository,
        account_repository=account_repository,
        vault=vault,
        broker=broker,
        brokered_session=brokered_session,
        terminal_io=terminal_io,
        audit_repository=audit_repository,
        id_generator=id_generator,
        call_log=call_log,
    )


def test_allowed_access_relays_and_closes_session_normally():
    harness = make_harness([make_policy(AccessEffect.ALLOW)])

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.ALLOW
    assert result.session is not None
    assert result.session.status is SessionStatus.CLOSED
    assert result.session.close_reason == "relay_completed"
    assert result.session.ended_at is not None
    assert harness.vault.calls == [make_account().credential_ref]
    assert len(harness.broker.calls) == 1
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_ACTIVE,
        AuditEventType.SESSION_CLOSED,
    ]
    assert harness.call_log == [
        "policy_repository.find_matching",
        "target_repository.get",
        "account_repository.find_for_target",
        "vault.resolve",
        "audit.append:access_allowed",
        "audit.append:session_opening",
        "session_broker.open_session",
        "audit.append:session_active",
        "brokered_session.relay",
        "brokered_session.close",
        "audit.append:session_closed",
    ]
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.max_durations == [MAX_SESSION_DURATION]
    assert harness.brokered_session.close_calls == 1
    assert sum(
        event.event_type is AuditEventType.SESSION_CLOSED
        for event in harness.audit_repository.events
    ) == 1
    assert all(
        event.event_type is not AuditEventType.SESSION_FAILED
        for event in harness.audit_repository.events
    )
    assert harness.call_log.index("audit.append:session_active") < (
        harness.call_log.index("brokered_session.relay")
    )


def test_wall_clock_rollback_still_closes_and_audits_session_once():
    harness = make_harness([make_policy(AccessEffect.ALLOW)])
    started_at = datetime(2026, 9, 12, 10, 5, tzinfo=UTC)
    rolled_back = started_at - timedelta(minutes=10)
    clock = SequenceClock([started_at] * 4 + [rolled_back])
    harness.service._clock = clock

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.CLOSED
    assert result.session.ended_at == started_at
    assert result.session.ended_at >= result.session.started_at
    assert harness.brokered_session.close_calls == 1
    terminal_events = [
        event
        for event in harness.audit_repository.events
        if event.event_type
        in {AuditEventType.SESSION_CLOSED, AuditEventType.SESSION_FAILED}
    ]
    assert [event.event_type for event in terminal_events] == [
        AuditEventType.SESSION_CLOSED
    ]
    assert terminal_events[0].timestamp == started_at


def test_wall_clock_rollback_still_fails_and_audits_relay_error_once():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_error=RuntimeError("controlled relay failure"),
    )
    started_at = datetime(2026, 9, 12, 10, 5, tzinfo=UTC)
    rolled_back = started_at - timedelta(minutes=10)
    clock = SequenceClock([started_at] * 4 + [rolled_back])
    harness.service._clock = clock

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "relay_failed"
    assert result.session.ended_at == started_at
    assert result.session.ended_at >= result.session.started_at
    assert harness.brokered_session.close_calls == 1
    terminal_events = [
        event
        for event in harness.audit_repository.events
        if event.event_type
        in {AuditEventType.SESSION_CLOSED, AuditEventType.SESSION_FAILED}
    ]
    assert [event.event_type for event in terminal_events] == [
        AuditEventType.SESSION_FAILED
    ]
    assert terminal_events[0].timestamp == started_at


def test_positive_max_session_duration_is_accepted_and_forwarded():
    duration = timedelta(seconds=45)
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        max_session_duration=duration,
    )

    harness.service.handle(PRINCIPAL, make_request(), harness.terminal_io)

    assert harness.brokered_session.max_durations == [duration]


@pytest.mark.parametrize(
    "duration",
    [timedelta(0), timedelta(microseconds=-1)],
)
def test_nonpositive_max_session_duration_is_rejected(
    duration: timedelta,
):
    with pytest.raises(
        ValueError,
        match="max_session_duration must be positive",
    ):
        make_harness(
            [make_policy(AccessEffect.ALLOW)],
            max_session_duration=duration,
        )


def test_max_duration_timeout_closes_session_after_relay(
    monkeypatch: pytest.MonkeyPatch,
):
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_outcome=RelayOutcome.MAX_DURATION_EXCEEDED,
    )
    original_mark_closed = Session.mark_closed

    def mark_closed(
        session: Session,
        ended_at: datetime,
        reason: str,
    ) -> None:
        harness.call_log.append("session.mark_closed")
        original_mark_closed(session, ended_at, reason)

    monkeypatch.setattr(
        access_service_module.Session,
        "mark_closed",
        mark_closed,
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.CLOSED
    assert result.session.close_reason == "max_duration_exceeded"
    assert result.session.ended_at is not None
    assert result.session.ended_at.tzinfo is not None
    assert result.session.ended_at.utcoffset() is not None
    assert harness.brokered_session.max_durations == [MAX_SESSION_DURATION]
    assert harness.brokered_session.close_calls == 1
    assert harness.call_log.index("audit.append:session_active") < (
        harness.call_log.index("brokered_session.relay")
    )
    assert harness.call_log.index("brokered_session.relay") < (
        harness.call_log.index("session.mark_closed")
    )
    assert harness.call_log.index("brokered_session.close") < (
        harness.call_log.index("session.mark_closed")
    )
    terminal_events = [
        event
        for event in harness.audit_repository.events
        if event.event_type
        in {AuditEventType.SESSION_CLOSED, AuditEventType.SESSION_FAILED}
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0].event_type is AuditEventType.SESSION_CLOSED
    assert terminal_events[0].result == "closed"
    assert terminal_events[0].reason_code == "max_duration_exceeded"
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in repr(result)
    assert all(
        INTERNAL_CREDENTIAL_BYTES.decode() not in repr(event)
        for event in harness.audit_repository.events
    )


def test_timeout_with_cleanup_failure_uses_broker_close_failure_semantics():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_outcome=RelayOutcome.MAX_DURATION_EXCEEDED,
        close_error=RuntimeError("controlled close failure"),
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "broker_close_failed"
    assert harness.brokered_session.close_calls == 1
    assert [
        event.event_type
        for event in harness.audit_repository.events
        if event.event_type
        in {AuditEventType.SESSION_CLOSED, AuditEventType.SESSION_FAILED}
    ] == [AuditEventType.SESSION_FAILED]


def test_allowed_access_does_not_expose_resolved_credential():
    harness = make_harness([make_policy(AccessEffect.ALLOW)])

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert {field.name for field in fields(AccessResult)} == {
        "decision",
        "session",
    }
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in repr(result)
    assert all(
        INTERNAL_CREDENTIAL_BYTES.decode() not in repr(event)
        for event in harness.audit_repository.events
    )


def test_explicit_deny_stops_before_vault_broker_and_session_creation():
    harness = make_harness([make_policy(AccessEffect.DENY)])

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "policy-deny"
    assert result.session is None
    assert harness.target_repository.calls == []
    assert harness.account_repository.calls == []
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.brokered_session.relay_calls == []
    assert harness.brokered_session.close_calls == 0
    assert harness.id_generator.calls == 1
    assert len(harness.audit_repository.events) == 1
    event = harness.audit_repository.events[0]
    assert event.event_type is AuditEventType.ACCESS_DENIED
    assert event.reason_code == "policy-deny"
    assert event.session_id is None


def test_no_matching_policy_uses_the_same_safe_deny_path():
    harness = make_harness([])

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "no_matching_policy"
    assert result.session is None
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_DENIED
    ]


def test_authenticated_identity_mismatch_stops_before_policy_and_access(
    monkeypatch: pytest.MonkeyPatch,
):
    session_construction_calls: list[dict[str, object]] = []

    def track_session_construction(**values: object) -> None:
        session_construction_calls.append(values)
        raise AssertionError("session must not be constructed")

    monkeypatch.setattr(
        access_service_module,
        "Session",
        track_session_construction,
    )
    spoofed_policy = AccessPolicy(
        id="policy-spoofed-user-allow",
        user_id="user-002",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=AccessEffect.ALLOW,
    )
    harness = make_harness([spoofed_policy])
    spoofed_request = AccessRequest(
        id="request-spoofed-user",
        user_id="user-002",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 12, 10, tzinfo=UTC),
    )

    result = harness.service.handle(
        PRINCIPAL,
        spoofed_request,
        harness.terminal_io,
    )

    assert result.decision == AccessDecision(
        effect=AccessEffect.DENY,
        reason="authenticated_identity_mismatch",
    )
    assert result.session is None
    assert harness.policy_repository.queries == []
    assert harness.target_repository.calls == []
    assert harness.account_repository.calls == []
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.brokered_session.relay_calls == []
    assert harness.brokered_session.close_calls == 0
    assert session_construction_calls == []
    assert harness.id_generator.calls == 1
    assert len(harness.audit_repository.events) == 1
    event = harness.audit_repository.events[0]
    assert event.event_type is AuditEventType.ACCESS_DENIED
    assert event.actor_user_id == "user-001"
    assert event.target_id == "target-001"
    assert event.reason_code == "authenticated_identity_mismatch"


def test_requires_approval_uses_the_same_safe_deny_path():
    harness = make_harness(
        [make_policy(AccessEffect.REQUIRES_APPROVAL)]
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "approval_not_supported"
    assert result.session is None
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_DENIED
    ]


def test_broker_open_failure_marks_session_failed_without_relay():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        broker_open_error=RuntimeError("controlled broker open failure"),
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "broker_open_failed"
    assert result.session.ended_at is not None
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_FAILED,
    ]
    assert harness.brokered_session.relay_calls == []
    assert harness.brokered_session.close_calls == 0
    assert sum(
        event.event_type is AuditEventType.SESSION_FAILED
        for event in harness.audit_repository.events
    ) == 1
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in repr(result)
    assert all(
        INTERNAL_CREDENTIAL_BYTES.decode() not in repr(event)
        for event in harness.audit_repository.events
    )


def test_relay_failure_marks_active_session_failed_and_closes_brokered_session():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_error=RuntimeError("controlled relay failure"),
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "relay_failed"
    assert result.session.ended_at is not None
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.close_calls == 1
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_ACTIVE,
        AuditEventType.SESSION_FAILED,
    ]
    assert harness.call_log.index("audit.append:session_active") < (
        harness.call_log.index("brokered_session.relay")
    )
    assert sum(
        event.event_type is AuditEventType.SESSION_FAILED
        for event in harness.audit_repository.events
    ) == 1
    assert all(
        event.event_type is not AuditEventType.SESSION_CLOSED
        for event in harness.audit_repository.events
    )


def test_brokered_session_close_failure_marks_session_failed():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        close_error=RuntimeError("controlled close failure"),
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "broker_close_failed"
    assert result.session.ended_at is not None
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.close_calls == 1
    assert harness.audit_repository.events[-1].event_type is (
        AuditEventType.SESSION_FAILED
    )
    assert sum(
        event.event_type is AuditEventType.SESSION_FAILED
        for event in harness.audit_repository.events
    ) == 1
    assert all(
        event.event_type is not AuditEventType.SESSION_CLOSED
        for event in harness.audit_repository.events
    )


def test_relay_failure_takes_precedence_when_cleanup_also_fails():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_error=RuntimeError("controlled relay failure"),
        close_error=RuntimeError("controlled close failure"),
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "relay_failed"
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.close_calls == 1
    assert sum(
        event.event_type is AuditEventType.SESSION_FAILED
        for event in harness.audit_repository.events
    ) == 1


class ControlledAuditFailure(RuntimeError):
    pass


class FailingAuditRepository(FakeAuditRepository):
    def __init__(self, fail_on: AuditEventType) -> None:
        super().__init__()
        self.fail_on = fail_on
        self.attempted_event_types: list[AuditEventType] = []

    def append(self, event: AuditEvent) -> None:
        self.attempted_event_types.append(event.event_type)
        if event.event_type is self.fail_on:
            raise ControlledAuditFailure("controlled audit failure")
        super().append(event)


def capture_failed_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Session]:
    failed_sessions: list[Session] = []
    original_mark_failed = Session.mark_failed

    def mark_failed(
        session: Session,
        ended_at: datetime,
        reason: str,
    ) -> None:
        original_mark_failed(session, ended_at, reason)
        failed_sessions.append(session)

    monkeypatch.setattr(
        access_service_module.Session,
        "mark_failed",
        mark_failed,
    )
    return failed_sessions


def capture_closed_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Session]:
    closed_sessions: list[Session] = []
    original_mark_closed = Session.mark_closed

    def mark_closed(
        session: Session,
        ended_at: datetime,
        reason: str,
    ) -> None:
        original_mark_closed(session, ended_at, reason)
        closed_sessions.append(session)

    monkeypatch.setattr(
        access_service_module.Session,
        "mark_closed",
        mark_closed,
    )
    return closed_sessions


def test_closed_audit_failure_preserves_closed_state_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
):
    closed_sessions = capture_closed_sessions(monkeypatch)
    repository = FailingAuditRepository(AuditEventType.SESSION_CLOSED)
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        audit_repository=repository,
    )

    with pytest.raises(ControlledAuditFailure) as raised:
        harness.service.handle(
            PRINCIPAL, make_request(), harness.terminal_io
        )

    assert str(raised.value) == "controlled audit failure"
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in str(raised.value)
    assert len(closed_sessions) == 1
    session = closed_sessions[0]
    assert session.status is SessionStatus.CLOSED
    assert session.close_reason == "relay_completed"
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.close_calls == 1
    assert harness.vault.calls == [make_account().credential_ref]
    assert repository.attempted_event_types == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_ACTIVE,
        AuditEventType.SESSION_CLOSED,
    ]
    assert all(
        event.event_type is not AuditEventType.SESSION_FAILED
        for event in repository.events
    )


def test_failed_audit_failure_preserves_failed_state_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
):
    failed_sessions = capture_failed_sessions(monkeypatch)
    repository = FailingAuditRepository(AuditEventType.SESSION_FAILED)
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        relay_error=RuntimeError("controlled relay failure"),
        close_error=RuntimeError("controlled cleanup failure"),
        audit_repository=repository,
    )

    with pytest.raises(ControlledAuditFailure) as raised:
        harness.service.handle(
            PRINCIPAL, make_request(), harness.terminal_io
        )

    assert str(raised.value) == "controlled audit failure"
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in str(raised.value)
    assert len(failed_sessions) == 1
    session = failed_sessions[0]
    assert session.status is SessionStatus.FAILED
    assert session.close_reason == "relay_failed"
    assert harness.brokered_session.relay_calls == [harness.terminal_io]
    assert harness.brokered_session.close_calls == 1
    assert harness.vault.calls == [make_account().credential_ref]
    assert repository.attempted_event_types == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_ACTIVE,
        AuditEventType.SESSION_FAILED,
    ]
    assert all(
        event.event_type is not AuditEventType.SESSION_CLOSED
        for event in repository.events
    )


def test_opening_audit_failure_marks_session_failed_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
):
    failed_sessions = capture_failed_sessions(monkeypatch)
    repository = FailingAuditRepository(AuditEventType.SESSION_OPENING)
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        audit_repository=repository,
    )

    with pytest.raises(ControlledAuditFailure):
        harness.service.handle(
            PRINCIPAL, make_request(), harness.terminal_io
        )

    assert len(failed_sessions) == 1
    session = failed_sessions[0]
    assert session.status is SessionStatus.FAILED
    assert session.ended_at is not None
    assert session.close_reason == "audit_persistence_failed"
    assert harness.broker.calls == []
    assert harness.brokered_session.close_calls == 0


def test_active_audit_failure_fails_session_and_preserves_audit_error(
    monkeypatch: pytest.MonkeyPatch,
):
    failed_sessions = capture_failed_sessions(monkeypatch)
    repository = FailingAuditRepository(AuditEventType.SESSION_ACTIVE)
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        close_error=RuntimeError("controlled close failure"),
        audit_repository=repository,
    )

    with pytest.raises(ControlledAuditFailure):
        harness.service.handle(
            PRINCIPAL, make_request(), harness.terminal_io
        )

    assert len(failed_sessions) == 1
    session = failed_sessions[0]
    assert session.status is SessionStatus.FAILED
    assert session.ended_at is not None
    assert session.close_reason == "audit_persistence_failed"
    assert harness.brokered_session.relay_calls == []
    assert harness.brokered_session.close_calls == 1


def test_missing_target_fails_closed_before_vault_or_broker():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        targets=[],
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "target_not_found"
    assert result.session is None
    assert harness.target_repository.calls == ["target-001"]
    assert harness.account_repository.calls == []
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.audit_repository.events[0].event_type is (
        AuditEventType.ACCESS_DENIED
    )


def test_missing_account_fails_closed_before_vault_or_broker():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        accounts=[],
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "account_not_found"
    assert result.session is None
    assert harness.target_repository.calls == ["target-001"]
    assert harness.account_repository.calls == ["target-001"]
    assert harness.vault.calls == []
    assert harness.broker.calls == []


def test_disabled_target_denies_before_account_vault_broker_or_session():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        targets=[make_target(enabled=False)],
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "target_disabled"
    assert result.session is None
    assert harness.target_repository.calls == ["target-001"]
    assert harness.account_repository.calls == []
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.call_log == [
        "policy_repository.find_matching",
        "target_repository.get",
        "audit.append:access_denied",
    ]
    event = harness.audit_repository.events[0]
    assert event.event_type is AuditEventType.ACCESS_DENIED
    assert event.reason_code == "target_disabled"
    assert event.session_id is None


def test_disabled_account_denies_before_vault_broker_or_session():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        accounts=[make_account(enabled=False)],
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "privileged_account_disabled"
    assert result.session is None
    assert harness.target_repository.calls == ["target-001"]
    assert harness.account_repository.calls == ["target-001"]
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.call_log == [
        "policy_repository.find_matching",
        "target_repository.get",
        "account_repository.find_for_target",
        "audit.append:access_denied",
    ]
    event = harness.audit_repository.events[0]
    assert event.event_type is AuditEventType.ACCESS_DENIED
    assert event.reason_code == "privileged_account_disabled"
    assert event.session_id is None


def test_missing_credential_fails_closed_before_broker():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        credential=None,
    )

    result = harness.service.handle(
        PRINCIPAL, make_request(), harness.terminal_io
    )

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "credential_not_found"
    assert result.session is None
    assert len(harness.vault.calls) == 1
    assert harness.broker.calls == []
    assert harness.audit_repository.events[0].event_type is (
        AuditEventType.ACCESS_DENIED
    )
