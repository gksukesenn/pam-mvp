from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class SessionStatus(StrEnum):
    OPENING = "opening"
    ACTIVE = "active"
    CLOSED = "closed"
    FAILED = "failed"


@dataclass
class Session:
    id: str
    request_id: str
    user_id: str
    target_id: str
    account_id: str
    status: SessionStatus
    started_at: datetime
    ended_at: datetime | None = None
    close_reason: str | None = None

    def __post_init__(self) -> None:
        ids = {
            "session id": self.id,
            "request id": self.request_id,
            "user id": self.user_id,
            "target id": self.target_id,
            "account id": self.account_id,
        }
        for name, value in ids.items():
            if not value.strip():
                raise ValueError(f"{name} cannot be empty")

        self._require_aware(self.started_at, "started_at")
        if self.ended_at is not None:
            self._require_aware(self.ended_at, "ended_at")

    def mark_active(self) -> None:
        if self.status is not SessionStatus.OPENING:
            raise ValueError("only an opening session can become active")
        self.status = SessionStatus.ACTIVE

    def mark_failed(self, ended_at: datetime, reason: str) -> None:
        if self.status not in {SessionStatus.OPENING, SessionStatus.ACTIVE}:
            raise ValueError("only an opening or active session can fail")
        self._require_aware(ended_at, "ended_at")
        self.status = SessionStatus.FAILED
        self.ended_at = ended_at
        self.close_reason = reason

    def mark_closed(self, ended_at: datetime, reason: str) -> None:
        if self.status is not SessionStatus.ACTIVE:
            raise ValueError("only an active session can close")
        self._require_aware(ended_at, "ended_at")
        self.status = SessionStatus.CLOSED
        self.ended_at = ended_at
        self.close_reason = reason

    @staticmethod
    def _require_aware(value: datetime, field_name: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must be timezone-aware")
