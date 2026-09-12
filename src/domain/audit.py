from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AuditEventType(StrEnum):
    ACCESS_ALLOWED = "access_allowed"
    ACCESS_DENIED = "access_denied"
    SESSION_OPENING = "session_opening"
    SESSION_ACTIVE = "session_active"
    SESSION_FAILED = "session_failed"


@dataclass(frozen=True)
class AuditEvent:
    id: str
    timestamp: datetime
    event_type: AuditEventType
    actor_user_id: str
    target_id: str
    session_id: str | None
    result: str
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            self.timestamp.tzinfo is None
            or self.timestamp.utcoffset() is None
        ):
            raise ValueError("timestamp must be timezone-aware")
