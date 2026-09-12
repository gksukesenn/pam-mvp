from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AccessAction(StrEnum):
    OPEN_PRIVILEGED_SESSION = "open_privileged_session"


class AccessEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass(frozen=True)
class AccessDecision:
    effect: AccessEffect
    reason: str


@dataclass
class AccessPolicy:
    id: str
    user_id: str
    target_id: str
    action: AccessAction
    effect: AccessEffect

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("access policy id cannot be empty")

        if not self.user_id.strip():
            raise ValueError("user id cannot be empty")

        if not self.target_id.strip():
            raise ValueError("target id cannot be empty")


@dataclass
class AccessRequest:
    id: str
    user_id: str
    target_id: str
    action: AccessAction
    requested_at: datetime

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("access request id cannot be empty")

        if not self.user_id.strip():
            raise ValueError("user id cannot be empty")

        if not self.target_id.strip():
            raise ValueError("target id cannot be empty")

        if (
            self.requested_at.tzinfo is None
            or self.requested_at.utcoffset() is None
        ):
            raise ValueError("requested_at must be timezone-aware")
