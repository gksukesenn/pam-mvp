from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime

import pytest

from src.domain.audit import AuditEvent, AuditEventType


def make_event(**overrides: object) -> AuditEvent:
    values = {
        "id": "event-001",
        "timestamp": datetime(2026, 9, 12, tzinfo=UTC),
        "event_type": AuditEventType.ACCESS_ALLOWED,
        "actor_user_id": "user-001",
        "target_id": "target-001",
        "session_id": "session-001",
        "result": "allowed",
    }
    values.update(overrides)
    return AuditEvent(**values)


def test_audit_event_is_immutable():
    event = make_event()

    with pytest.raises(FrozenInstanceError):
        event.result = "changed"


def test_audit_event_rejects_naive_timestamp():
    with pytest.raises(
        ValueError,
        match="timestamp must be timezone-aware",
    ):
        make_event(timestamp=datetime(2026, 9, 12))


def test_audit_event_exposes_no_plaintext_secret_field():
    field_names = {field.name for field in fields(AuditEvent)}
    forbidden_names = {
        "password",
        "secret",
        "credential",
        "master_key",
        "token",
        "private_key",
    }

    assert field_names.isdisjoint(forbidden_names)
