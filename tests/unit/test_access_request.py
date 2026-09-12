from datetime import UTC, datetime

import pytest

from src.domain.access import AccessAction, AccessRequest


def test_access_request_can_be_created():
    requested_at = datetime(2026, 9, 12, 10, 30, tzinfo=UTC)

    request = AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=requested_at,
    )

    assert request.id == "request-001"
    assert request.user_id == "user-001"
    assert request.target_id == "target-001"
    assert request.action is AccessAction.OPEN_PRIVILEGED_SESSION
    assert request.requested_at is requested_at


def test_access_request_rejects_blank_id():
    with pytest.raises(ValueError, match="access request id cannot be empty"):
        AccessRequest(
            id="",
            user_id="user-001",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            requested_at=datetime(2026, 9, 12, tzinfo=UTC),
        )


def test_access_request_accepts_timezone_aware_requested_at():
    request = AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 12, tzinfo=UTC),
    )

    assert request.requested_at.utcoffset() is not None


def test_access_request_rejects_naive_requested_at():
    with pytest.raises(
        ValueError,
        match="requested_at must be timezone-aware",
    ):
        AccessRequest(
            id="request-001",
            user_id="user-001",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            requested_at=datetime(2026, 9, 12),
        )
