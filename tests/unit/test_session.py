from datetime import UTC, datetime

import pytest

from src.domain.session import Session, SessionStatus


def make_session(**overrides: object) -> Session:
    values = {
        "id": "session-001",
        "request_id": "request-001",
        "user_id": "user-001",
        "target_id": "target-001",
        "account_id": "account-001",
        "status": SessionStatus.OPENING,
        "started_at": datetime(2026, 9, 12, tzinfo=UTC),
    }
    values.update(overrides)
    return Session(**values)


def test_session_can_be_created_in_opening_state():
    session = make_session()

    assert session.status is SessionStatus.OPENING
    assert session.ended_at is None
    assert session.close_reason is None


@pytest.mark.parametrize(
    "field_name",
    ["id", "request_id", "user_id", "target_id", "account_id"],
)
def test_session_rejects_blank_ids(field_name: str):
    with pytest.raises(ValueError, match="cannot be empty"):
        make_session(**{field_name: "   "})


def test_session_rejects_naive_started_at():
    with pytest.raises(
        ValueError,
        match="started_at must be timezone-aware",
    ):
        make_session(started_at=datetime(2026, 9, 12))


def test_session_rejects_naive_ended_at():
    with pytest.raises(
        ValueError,
        match="ended_at must be timezone-aware",
    ):
        make_session(ended_at=datetime(2026, 9, 12))


def test_opening_session_can_become_active():
    session = make_session()

    session.mark_active()

    assert session.status is SessionStatus.ACTIVE


def test_opening_session_can_fail():
    session = make_session()
    ended_at = datetime(2026, 9, 12, 10, 5, tzinfo=UTC)

    session.mark_failed(ended_at=ended_at, reason="broker_failed")

    assert session.status is SessionStatus.FAILED
    assert session.ended_at is ended_at
    assert session.close_reason == "broker_failed"


def test_active_session_can_close():
    session = make_session()
    session.mark_active()
    ended_at = datetime(2026, 9, 12, 10, 5, tzinfo=UTC)

    session.mark_closed(ended_at=ended_at, reason="relay_completed")

    assert session.status is SessionStatus.CLOSED
    assert session.ended_at is ended_at
    assert session.close_reason == "relay_completed"


def test_active_session_can_fail():
    session = make_session()
    session.mark_active()

    session.mark_failed(
        ended_at=datetime(2026, 9, 12, 10, 5, tzinfo=UTC),
        reason="relay_failed",
    )

    assert session.status is SessionStatus.FAILED
    assert session.close_reason == "relay_failed"


@pytest.mark.parametrize(
    "terminal_status",
    [SessionStatus.CLOSED, SessionStatus.FAILED],
)
def test_terminal_session_cannot_become_active(
    terminal_status: SessionStatus,
):
    session = make_session(status=terminal_status)

    with pytest.raises(
        ValueError,
        match="only an opening session can become active",
    ):
        session.mark_active()
