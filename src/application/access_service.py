from dataclasses import dataclass

from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import AccessDecision, AccessEffect, AccessRequest
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.session import Session, SessionStatus
from src.ports.access_dependencies import (
    AuditRepository,
    Clock,
    IdGenerator,
    PrivilegedAccountRepository,
    SessionBroker,
    TargetRepository,
    VaultPort,
)


@dataclass(frozen=True)
class AccessResult:
    decision: AccessDecision
    session: Session | None


class AccessService:
    def __init__(
        self,
        policy_evaluator: PolicyEvaluator,
        target_repository: TargetRepository,
        account_repository: PrivilegedAccountRepository,
        vault: VaultPort,
        session_broker: SessionBroker,
        audit_repository: AuditRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._policy_evaluator = policy_evaluator
        self._target_repository = target_repository
        self._account_repository = account_repository
        self._vault = vault
        self._session_broker = session_broker
        self._audit_repository = audit_repository
        self._clock = clock
        self._id_generator = id_generator

    def handle(self, request: AccessRequest) -> AccessResult:
        decision = self._policy_evaluator.evaluate(request)
        if decision.effect is not AccessEffect.ALLOW:
            return self._deny(request, decision)

        target = self._target_repository.get(request.target_id)
        if target is None:
            return self._deny_with_reason(request, "target_not_found")
        if not target.enabled:
            return self._deny_with_reason(request, "target_disabled")

        account = self._account_repository.find_for_target(target.id)
        if account is None:
            return self._deny_with_reason(request, "account_not_found")
        if not account.enabled:
            return self._deny_with_reason(request, "account_disabled")
        if account.target_id != target.id:
            return self._deny_with_reason(request, "account_target_mismatch")

        credential = self._vault.resolve(account.credential_ref)
        if credential is None:
            return self._deny_with_reason(request, "credential_not_found")

        session = Session(
            id=self._id_generator.new_id(),
            request_id=request.id,
            user_id=request.user_id,
            target_id=target.id,
            account_id=account.id,
            status=SessionStatus.OPENING,
            started_at=self._clock.now(),
        )
        self._append_event(
            request=request,
            event_type=AuditEventType.ACCESS_ALLOWED,
            session_id=session.id,
            result="allowed",
            reason_code=decision.reason,
        )
        self._append_event(
            request=request,
            event_type=AuditEventType.SESSION_OPENING,
            session_id=session.id,
            result="opening",
        )

        opened = self._session_broker.open_session(
            target=target,
            privileged_account=account,
            credential=credential,
        )
        if opened:
            session.mark_active()
            self._append_event(
                request=request,
                event_type=AuditEventType.SESSION_ACTIVE,
                session_id=session.id,
                result="active",
            )
        else:
            session.mark_failed(
                ended_at=self._clock.now(),
                reason="broker_failed",
            )
            self._append_event(
                request=request,
                event_type=AuditEventType.SESSION_FAILED,
                session_id=session.id,
                result="failed",
                reason_code="broker_failed",
            )

        return AccessResult(decision=decision, session=session)

    def _deny_with_reason(
        self,
        request: AccessRequest,
        reason: str,
    ) -> AccessResult:
        return self._deny(
            request,
            AccessDecision(effect=AccessEffect.DENY, reason=reason),
        )

    def _deny(
        self,
        request: AccessRequest,
        decision: AccessDecision,
    ) -> AccessResult:
        self._append_event(
            request=request,
            event_type=AuditEventType.ACCESS_DENIED,
            session_id=None,
            result="denied",
            reason_code=decision.reason,
        )
        return AccessResult(decision=decision, session=None)

    def _append_event(
        self,
        request: AccessRequest,
        event_type: AuditEventType,
        session_id: str | None,
        result: str,
        reason_code: str | None = None,
    ) -> None:
        self._audit_repository.append(
            AuditEvent(
                id=self._id_generator.new_id(),
                timestamp=self._clock.now(),
                event_type=event_type,
                actor_user_id=request.user_id,
                target_id=request.target_id,
                session_id=session_id,
                result=result,
                reason_code=reason_code,
            )
        )
