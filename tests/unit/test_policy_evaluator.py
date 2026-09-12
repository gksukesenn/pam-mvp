from datetime import UTC, datetime

from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from tests.fakes.policy_repository import FakePolicyRepository


def make_policy(
    policy_id: str,
    effect: AccessEffect,
) -> AccessPolicy:
    return AccessPolicy(
        id=policy_id,
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
        requested_at=datetime(2026, 9, 12, tzinfo=UTC),
    )


def test_no_matching_policy_denies_access():
    evaluator = PolicyEvaluator(FakePolicyRepository([]))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "no_matching_policy"


def test_one_allow_policy_allows_access():
    policy = make_policy("policy-allow", AccessEffect.ALLOW)
    evaluator = PolicyEvaluator(FakePolicyRepository([policy]))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.ALLOW
    assert decision.reason == "policy-allow"


def test_one_deny_policy_denies_access():
    policy = make_policy("policy-deny", AccessEffect.DENY)
    evaluator = PolicyEvaluator(FakePolicyRepository([policy]))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "policy-deny"


def test_deny_takes_precedence_over_allow():
    policies = [
        make_policy("policy-allow", AccessEffect.ALLOW),
        make_policy("policy-deny", AccessEffect.DENY),
    ]
    evaluator = PolicyEvaluator(FakePolicyRepository(policies))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "policy-deny"


def test_deny_takes_precedence_over_requires_approval():
    policies = [
        make_policy(
            "policy-requires-approval",
            AccessEffect.REQUIRES_APPROVAL,
        ),
        make_policy("policy-deny", AccessEffect.DENY),
    ]
    evaluator = PolicyEvaluator(FakePolicyRepository(policies))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "policy-deny"


def test_multiple_allow_policies_allow_access():
    policies = [
        make_policy("policy-allow-001", AccessEffect.ALLOW),
        make_policy("policy-allow-002", AccessEffect.ALLOW),
    ]
    evaluator = PolicyEvaluator(FakePolicyRepository(policies))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.ALLOW
    assert decision.reason == "policy-allow-001"


def test_requires_approval_denies_access_when_approval_is_unsupported():
    policy = make_policy(
        "policy-requires-approval",
        AccessEffect.REQUIRES_APPROVAL,
    )
    evaluator = PolicyEvaluator(FakePolicyRepository([policy]))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "approval_not_supported"


def test_requires_approval_takes_precedence_over_allow():
    policies = [
        make_policy("policy-allow", AccessEffect.ALLOW),
        make_policy(
            "policy-requires-approval",
            AccessEffect.REQUIRES_APPROVAL,
        ),
    ]
    evaluator = PolicyEvaluator(FakePolicyRepository(policies))

    decision = evaluator.evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "approval_not_supported"


def test_evaluator_queries_repository_with_request_values():
    repository = FakePolicyRepository([])
    evaluator = PolicyEvaluator(repository)
    request = make_request()

    evaluator.evaluate(request)

    assert repository.queries == [
        (
            request.user_id,
            request.target_id,
            request.action,
        )
    ]


def test_evaluator_does_not_mutate_returned_policies():
    policies = [
        make_policy("policy-allow", AccessEffect.ALLOW),
        make_policy("policy-deny", AccessEffect.DENY),
    ]
    policy_state = [
        (
            policy.id,
            policy.user_id,
            policy.target_id,
            policy.action,
            policy.effect,
        )
        for policy in policies
    ]
    repository = FakePolicyRepository(policies)
    evaluator = PolicyEvaluator(repository)

    evaluator.evaluate(make_request())

    assert repository.last_result == policies
    assert [
        (
            policy.id,
            policy.user_id,
            policy.target_id,
            policy.action,
            policy.effect,
        )
        for policy in policies
    ] == policy_state
