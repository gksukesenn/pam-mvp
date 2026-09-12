import pytest

from src.domain.access import AccessAction, AccessEffect, AccessPolicy


def test_access_policy_can_be_created():
    policy = AccessPolicy(
        id="policy-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=AccessEffect.ALLOW,
    )

    assert policy.id == "policy-001"
    assert policy.user_id == "user-001"
    assert policy.target_id == "target-001"
    assert policy.action is AccessAction.OPEN_PRIVILEGED_SESSION
    assert policy.effect is AccessEffect.ALLOW


def test_access_policy_rejects_blank_id():
    with pytest.raises(ValueError, match="access policy id cannot be empty"):
        AccessPolicy(
            id="",
            user_id="user-001",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            effect=AccessEffect.ALLOW,
        )


def test_access_policy_rejects_blank_user_id():
    with pytest.raises(ValueError, match="user id cannot be empty"):
        AccessPolicy(
            id="policy-001",
            user_id="   ",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            effect=AccessEffect.ALLOW,
        )


def test_access_policy_rejects_blank_target_id():
    with pytest.raises(ValueError, match="target id cannot be empty"):
        AccessPolicy(
            id="policy-001",
            user_id="user-001",
            target_id="",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            effect=AccessEffect.ALLOW,
        )
