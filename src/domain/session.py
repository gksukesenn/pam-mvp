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

        if not isinstance(self.status, SessionStatus):
            raise ValueError("status must be a SessionStatus")

        self._require_aware(self.started_at, "started_at")
        if self.ended_at is not None:
            self._require_aware(self.ended_at, "ended_at")
            self._require_not_before_start(self.ended_at)

        if self.status in {SessionStatus.OPENING, SessionStatus.ACTIVE}:
            if self.ended_at is not None:
                raise ValueError(
                    "an opening or active session cannot have ended_at"
                )
            if self.close_reason is not None:
                raise ValueError(
                    "an opening or active session cannot have close_reason"
                )
        elif self.status in {SessionStatus.CLOSED, SessionStatus.FAILED}:
            if self.ended_at is None:
                raise ValueError("a terminal session must have ended_at")
            self._require_reason(self.close_reason)

    def mark_active(self) -> None:
        if self.status is not SessionStatus.OPENING:
            raise ValueError("only an opening session can become active")
        self.status = SessionStatus.ACTIVE

    def mark_failed(self, ended_at: datetime, reason: str) -> None:
        if self.status not in {SessionStatus.OPENING, SessionStatus.ACTIVE}:
            raise ValueError("only an opening or active session can fail")
        self._validate_terminal_values(ended_at, reason)
        self.status = SessionStatus.FAILED
        self.ended_at = ended_at
        self.close_reason = reason

    def mark_closed(self, ended_at: datetime, reason: str) -> None:
        if self.status is not SessionStatus.ACTIVE:
            raise ValueError("only an active session can close")
        self._validate_terminal_values(ended_at, reason)
        self.status = SessionStatus.CLOSED
        self.ended_at = ended_at
        self.close_reason = reason

    def _validate_terminal_values(
        self,
        ended_at: datetime,
        reason: str,
    ) -> None:
        self._require_aware(ended_at, "ended_at")
        self._require_not_before_start(ended_at)
        self._require_reason(reason)

    def _require_not_before_start(self, ended_at: datetime) -> None:
        if ended_at < self.started_at:
            raise ValueError("ended_at cannot be earlier than started_at")

    @staticmethod
    def _require_reason(reason: str | None) -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("close_reason cannot be empty")

    @staticmethod
    def _require_aware(value: datetime, field_name: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must be timezone-aware")
