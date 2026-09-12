import pytest

from src.domain.access import AccessAction, AccessDecision, AccessEffect


def test_access_action_has_open_privileged_session():
    assert (
        AccessAction.OPEN_PRIVILEGED_SESSION.value
        == "open_privileged_session"
    )


def test_access_decision_can_represent_allow():
    decision = AccessDecision(
        effect=AccessEffect.ALLOW,
        reason="policy-001",
    )

    assert decision.effect is AccessEffect.ALLOW
    assert decision.reason == "policy-001"


def test_access_decision_can_represent_deny():
    decision = AccessDecision(
        effect=AccessEffect.DENY,
        reason="no_matching_policy",
    )

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "no_matching_policy"


def test_access_decision_is_immutable():
    decision = AccessDecision(
        effect=AccessEffect.ALLOW,
        reason="policy-001",
    )

    with pytest.raises(Exception):
        decision.effect = AccessEffect.DENY
