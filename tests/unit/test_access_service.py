from dataclasses import dataclass, fields
from datetime import UTC, datetime

from src.application.access_service import AccessResult, AccessService
from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.domain.audit import AuditEventType
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.session import SessionStatus
from src.domain.target import HostKeyFingerprint, Target
from src.ports.access_dependencies import BrokerCredential
from tests.fakes.access_dependencies import (
    FakeAuditRepository,
    FakeIdGenerator,
    FakePrivilegedAccountRepository,
    FakeSessionBroker,
    FakeTargetRepository,
    FakeVault,
    FixedClock,
)
from tests.fakes.policy_repository import FakePolicyRepository


INTERNAL_CREDENTIAL_BYTES = b"vault-internal-password"
INTERNAL_CREDENTIAL = BrokerCredential(INTERNAL_CREDENTIAL_BYTES)


@dataclass
class Harness:
    service: AccessService
    policy_repository: FakePolicyRepository
    target_repository: FakeTargetRepository
    account_repository: FakePrivilegedAccountRepository
    vault: FakeVault
    broker: FakeSessionBroker
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


def make_target() -> Target:
    return Target(
        id="target-001",
        name="production-server",
        host="server.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:abc123"),
    )


def make_account() -> PrivilegedAccount:
    return PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=CredentialRef("credential-001"),
    )


def make_harness(
    policies: list[AccessPolicy],
    *,
    targets: list[Target] | None = None,
    accounts: list[PrivilegedAccount] | None = None,
    credential: BrokerCredential | None = INTERNAL_CREDENTIAL,
    broker_succeeds: bool = True,
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
    broker = FakeSessionBroker(broker_succeeds, call_log)
    audit_repository = FakeAuditRepository(call_log)
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
    )
    return Harness(
        service=service,
        policy_repository=policy_repository,
        target_repository=target_repository,
        account_repository=account_repository,
        vault=vault,
        broker=broker,
        audit_repository=audit_repository,
        id_generator=id_generator,
        call_log=call_log,
    )


def test_allowed_access_opens_active_session_and_audits_each_step():
    harness = make_harness([make_policy(AccessEffect.ALLOW)])

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.ALLOW
    assert result.session is not None
    assert result.session.status is SessionStatus.ACTIVE
    assert harness.vault.calls == [make_account().credential_ref]
    assert len(harness.broker.calls) == 1
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_ACTIVE,
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
    ]


def test_allowed_access_does_not_expose_resolved_credential():
    harness = make_harness([make_policy(AccessEffect.ALLOW)])

    result = harness.service.handle(make_request())

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

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "policy-deny"
    assert result.session is None
    assert harness.target_repository.calls == []
    assert harness.account_repository.calls == []
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert harness.id_generator.calls == 1
    assert len(harness.audit_repository.events) == 1
    event = harness.audit_repository.events[0]
    assert event.event_type is AuditEventType.ACCESS_DENIED
    assert event.reason_code == "policy-deny"
    assert event.session_id is None


def test_no_matching_policy_uses_the_same_safe_deny_path():
    harness = make_harness([])

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "no_matching_policy"
    assert result.session is None
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_DENIED
    ]


def test_requires_approval_uses_the_same_safe_deny_path():
    harness = make_harness(
        [make_policy(AccessEffect.REQUIRES_APPROVAL)]
    )

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "approval_not_supported"
    assert result.session is None
    assert harness.vault.calls == []
    assert harness.broker.calls == []
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_DENIED
    ]


def test_broker_failure_marks_session_failed_without_exposing_credential():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        broker_succeeds=False,
    )

    result = harness.service.handle(make_request())

    assert result.session is not None
    assert result.session.status is SessionStatus.FAILED
    assert result.session.close_reason == "broker_failed"
    assert result.session.ended_at is not None
    assert [event.event_type for event in harness.audit_repository.events] == [
        AuditEventType.ACCESS_ALLOWED,
        AuditEventType.SESSION_OPENING,
        AuditEventType.SESSION_FAILED,
    ]
    assert INTERNAL_CREDENTIAL_BYTES.decode() not in repr(result)
    assert all(
        INTERNAL_CREDENTIAL_BYTES.decode() not in repr(event)
        for event in harness.audit_repository.events
    )


def test_missing_target_fails_closed_before_vault_or_broker():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        targets=[],
    )

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "target_not_found"
    assert result.session is None
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

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "account_not_found"
    assert result.session is None
    assert harness.vault.calls == []
    assert harness.broker.calls == []


def test_missing_credential_fails_closed_before_broker():
    harness = make_harness(
        [make_policy(AccessEffect.ALLOW)],
        credential=None,
    )

    result = harness.service.handle(make_request())

    assert result.decision.effect is AccessEffect.DENY
    assert result.decision.reason == "credential_not_found"
    assert result.session is None
    assert len(harness.vault.calls) == 1
    assert harness.broker.calls == []
    assert harness.audit_repository.events[0].event_type is (
        AuditEventType.ACCESS_DENIED
    )
