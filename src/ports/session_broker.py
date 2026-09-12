from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from src.domain.privileged_account import PrivilegedAccount
from src.domain.target import Target


@dataclass(frozen=True, repr=False)
class BrokerCredential:
    _value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self._value, bytes):
            raise TypeError("broker credential value must be bytes")

    def as_bytes(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "BrokerCredential(<redacted>)"


class TerminalIO(Protocol):
    def fileno(self) -> int: ...

    def read_input(self, max_bytes: int) -> bytes: ...

    def write_output(self, data: bytes) -> None: ...


class RelayOutcome(StrEnum):
    COMPLETED = "completed"
    MAX_DURATION_EXCEEDED = "max_duration_exceeded"


class BrokeredSession(Protocol):
    def relay(
        self,
        terminal_io: TerminalIO,
        max_duration: timedelta,
    ) -> RelayOutcome: ...

    def close(self) -> None: ...


class SessionBroker(Protocol):
    def open_session(
        self,
        target: Target,
        privileged_account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> BrokeredSession: ...
