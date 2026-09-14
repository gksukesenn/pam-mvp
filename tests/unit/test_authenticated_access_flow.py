from datetime import UTC, datetime

import pytest

from src.application.authentication_service import (
    AuthenticationFailedError,
    AuthenticationService,
)
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.domain.user import User
from src.ports.authentication import StoredUserAuthentication
from tests.unit.test_access_service import make_harness

PASSWORD = "focused-flow-password"  # pragma: allowlist secret


class FlowUserAuthenticationRepository:
    def find_by_username(
        self,
        username: str,
    ) -> StoredUserAuthentication | None:
        if username != "goksu":
            return None
        return StoredUserAuthentication(
            user=User(id="user-001", username="goksu"),
            password_hash="encoded-flow-hash",  # pragma: allowlist secret
        )


class FlowPasswordHasher:
    def hash_password(self, password: str) -> str:
        return "$argon2id$flow-dummy-hash"

    def verify(self, password: str, encoded_hash: str) -> bool:
        return password == PASSWORD and encoded_hash == "encoded-flow-hash"


def make_request(user_id: str = "user-001") -> AccessRequest:
    return AccessRequest(
        id="request-001",
        user_id=user_id,
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 13, tzinfo=UTC),
    )


def make_allow_policy(user_id: str = "user-001") -> AccessPolicy:
    return AccessPolicy(
        id=f"policy-{user_id}-allow",
        user_id=user_id,
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=AccessEffect.ALLOW,
    )


def test_authentication_then_access_flow_enforces_authenticated_identity():
    authentication = AuthenticationService(
        FlowUserAuthenticationRepository(),
        FlowPasswordHasher(),
    )

    allowed = make_harness([make_allow_policy()])
    principal = authentication.authenticate("goksu", PASSWORD)
    allowed_result = allowed.service.handle(
        principal,
        make_request(),
        allowed.terminal_io,
    )
    assert allowed_result.decision.effect is AccessEffect.ALLOW
    assert allowed_result.session is not None
    assert len(allowed.vault.calls) == 1
    assert len(allowed.broker.calls) == 1

    rejected_login = make_harness([make_allow_policy()])
    with pytest.raises(AuthenticationFailedError):
        failed_principal = authentication.authenticate("goksu", "wrong")
        rejected_login.service.handle(
            failed_principal,
            make_request(),
            rejected_login.terminal_io,
        )
    assert rejected_login.policy_repository.queries == []
    assert rejected_login.target_repository.calls == []
    assert rejected_login.vault.calls == []
    assert rejected_login.broker.calls == []

    spoofed = make_harness([make_allow_policy("user-002")])
    spoofed_result = spoofed.service.handle(
        principal,
        make_request("user-002"),
        spoofed.terminal_io,
    )
    assert spoofed_result.decision.effect is AccessEffect.DENY
    assert spoofed_result.decision.reason == "authenticated_identity_mismatch"
    assert spoofed_result.session is None
    assert spoofed.policy_repository.queries == []
    assert spoofed.target_repository.calls == []
    assert spoofed.vault.calls == []
    assert spoofed.broker.calls == []
