from src.domain.access import (
    AccessDecision,
    AccessEffect,
    AccessRequest,
)
from src.ports.policy_repository import PolicyRepository


class PolicyEvaluator:
    def __init__(self, policy_repository: PolicyRepository) -> None:
        self._policy_repository = policy_repository

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        policies = self._policy_repository.find_matching(
            user_id=request.user_id,
            target_id=request.target_id,
            action=request.action,
        )

        denying_policy = next(
            (
                policy
                for policy in policies
                if policy.effect is AccessEffect.DENY
            ),
            None,
        )
        if denying_policy is not None:
            return AccessDecision(
                effect=AccessEffect.DENY,
                reason=denying_policy.id,
            )

        if any(
            policy.effect is AccessEffect.REQUIRES_APPROVAL
            for policy in policies
        ):
            return AccessDecision(
                effect=AccessEffect.DENY,
                reason="approval_not_supported",
            )

        allowing_policy = next(
            (
                policy
                for policy in policies
                if policy.effect is AccessEffect.ALLOW
            ),
            None,
        )
        if allowing_policy is not None:
            return AccessDecision(
                effect=AccessEffect.ALLOW,
                reason=allowing_policy.id,
            )

        return AccessDecision(
            effect=AccessEffect.DENY,
            reason="no_matching_policy",
        )
