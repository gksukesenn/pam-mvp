from datetime import UTC, datetime

import pytest

from src.domain.session import Session, SessionStatus


STARTED_AT = datetime(2026, 9, 12, 10, tzinfo=UTC)
ENDED_AT = datetime(2026, 9, 12, 10, 5, tzinfo=UTC)


def make_session(**overrides: object) -> Session:
    values = {
        "id": "session-001",
        "request_id": "request-001",
        "user_id": "user-001",
        "target_id": "target-001",
        "account_id": "account-001",
        "status": SessionStatus.OPENING,
        "started_at": STARTED_AT,
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


def test_session_rejects_non_enum_status():
    with pytest.raises(ValueError, match="status must be a SessionStatus"):
        make_session(status="opening")


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
    assert session.ended_at is None
    assert session.close_reason is None


def test_opening_session_can_fail():
    session = make_session()

    session.mark_failed(ended_at=ENDED_AT, reason="broker_failed")

    assert session.status is SessionStatus.FAILED
    assert session.ended_at is ENDED_AT
    assert session.close_reason == "broker_failed"


def test_active_session_can_close():
    session = make_session()
    session.mark_active()

    session.mark_closed(ended_at=ENDED_AT, reason="relay_completed")

    assert session.status is SessionStatus.CLOSED
    assert session.ended_at is ENDED_AT
    assert session.close_reason == "relay_completed"


def test_active_session_can_fail():
    session = make_session()
    session.mark_active()

    session.mark_failed(
        ended_at=ENDED_AT,
        reason="relay_failed",
    )

    assert session.status is SessionStatus.FAILED
    assert session.ended_at is ENDED_AT
    assert session.close_reason == "relay_failed"


@pytest.mark.parametrize(
    ("initial_status", "transition"),
    [
        (SessionStatus.OPENING, "mark_closed"),
        (SessionStatus.ACTIVE, "mark_active"),
        (SessionStatus.CLOSED, "mark_active"),
        (SessionStatus.CLOSED, "mark_failed"),
        (SessionStatus.CLOSED, "mark_closed"),
        (SessionStatus.FAILED, "mark_active"),
        (SessionStatus.FAILED, "mark_closed"),
        (SessionStatus.FAILED, "mark_failed"),
    ],
)
def test_invalid_transition_is_rejected_without_mutating_session(
    initial_status: SessionStatus,
    transition: str,
):
    session = make_session()
    if initial_status is SessionStatus.ACTIVE:
        session.mark_active()
    elif initial_status is SessionStatus.CLOSED:
        session.mark_active()
        session.mark_closed(ENDED_AT, "relay_completed")
    elif initial_status is SessionStatus.FAILED:
        session.mark_failed(ENDED_AT, "controlled_failure")
    original_state = (
        session.status,
        session.ended_at,
        session.close_reason,
    )

    with pytest.raises(ValueError):
        if transition == "mark_active":
            session.mark_active()
        elif transition == "mark_closed":
            session.mark_closed(ENDED_AT, "relay_completed")
        else:
            session.mark_failed(ENDED_AT, "controlled_failure")

    assert (
        session.status,
        session.ended_at,
        session.close_reason,
    ) == original_state


@pytest.mark.parametrize("transition", ["closed", "failed"])
def test_terminal_transition_rejects_time_before_start_without_mutation(
    transition: str,
):
    session = make_session()
    if transition == "closed":
        session.mark_active()
    ended_before_start = datetime(2026, 9, 12, 9, 59, tzinfo=UTC)
    original_status = session.status

    with pytest.raises(
        ValueError,
        match="ended_at cannot be earlier than started_at",
    ):
        if transition == "closed":
            session.mark_closed(ended_before_start, "relay_completed")
        else:
            session.mark_failed(ended_before_start, "broker_failed")

    assert session.status is original_status
    assert session.ended_at is None
    assert session.close_reason is None


@pytest.mark.parametrize("transition", ["closed", "failed"])
def test_terminal_transition_rejects_naive_timestamp(
    transition: str,
):
    session = make_session()
    if transition == "closed":
        session.mark_active()

    with pytest.raises(
        ValueError,
        match="ended_at must be timezone-aware",
    ):
        if transition == "closed":
            session.mark_closed(
                datetime(2026, 9, 12, 10, 5),
                "relay_completed",
            )
        else:
            session.mark_failed(
                datetime(2026, 9, 12, 10, 5),
                "broker_failed",
            )

    assert session.ended_at is None


def test_constructor_rejects_ended_at_before_started_at():
    with pytest.raises(
        ValueError,
        match="ended_at cannot be earlier than started_at",
    ):
        make_session(
            status=SessionStatus.FAILED,
            ended_at=datetime(2026, 9, 12, 9, 59, tzinfo=UTC),
            close_reason="broker_failed",
        )


@pytest.mark.parametrize(
    "status",
    [SessionStatus.OPENING, SessionStatus.ACTIVE],
)
def test_nonterminal_session_cannot_have_terminal_values(
    status: SessionStatus,
):
    with pytest.raises(
        ValueError,
        match="cannot have ended_at",
    ):
        make_session(
            status=status,
            ended_at=ENDED_AT,
            close_reason="relay_completed",
        )


@pytest.mark.parametrize(
    "status",
    [SessionStatus.CLOSED, SessionStatus.FAILED],
)
def test_terminal_session_requires_ended_at(status: SessionStatus):
    with pytest.raises(
        ValueError,
        match="terminal session must have ended_at",
    ):
        make_session(status=status)


@pytest.mark.parametrize("transition", ["closed", "failed"])
def test_terminal_transition_requires_nonblank_reason(transition: str):
    session = make_session()
    if transition == "closed":
        session.mark_active()

    with pytest.raises(ValueError, match="close_reason cannot be empty"):
        if transition == "closed":
            session.mark_closed(ENDED_AT, "   ")
        else:
            session.mark_failed(ENDED_AT, "   ")

    assert session.ended_at is None
