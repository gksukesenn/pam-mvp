from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from src.domain.audit import AuditEvent
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
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


class VaultPort(Protocol):
    def resolve(
        self,
        credential_ref: CredentialRef,
    ) -> BrokerCredential | None: ...


class SessionBroker(Protocol):
    def open_session(
        self,
        target: Target,
        privileged_account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> bool: ...


class AuditRepository(Protocol):
    def append(self, event: AuditEvent) -> None: ...


class TargetRepository(Protocol):
    def get(self, target_id: str) -> Target | None: ...


class PrivilegedAccountRepository(Protocol):
    def find_for_target(
        self,
        target_id: str,
    ) -> PrivilegedAccount | None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new_id(self) -> str: ...
