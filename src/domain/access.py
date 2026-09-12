from dataclasses import dataclass
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
    