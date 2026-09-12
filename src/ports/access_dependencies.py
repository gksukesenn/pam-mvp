from datetime import datetime
from typing import Protocol

from src.domain.audit import AuditEvent
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import Target


class VaultPort(Protocol):
    def resolve(self, credential_ref: CredentialRef) -> object | None: ...


class SessionBroker(Protocol):
    def open_session(
        self,
        target: Target,
        privileged_account: PrivilegedAccount,
        credential: object,
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
