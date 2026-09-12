from datetime import datetime

from src.domain.audit import AuditEvent
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import Target
from src.ports.session_broker import BrokerCredential, TerminalIO


class FakeVault:
    def __init__(
        self,
        credential: BrokerCredential | None,
        call_log: list[str] | None = None,
    ) -> None:
        self.credential = credential
        self.call_log = call_log
        self.calls: list[CredentialRef] = []

    def resolve(
        self,
        credential_ref: CredentialRef,
    ) -> BrokerCredential | None:
        if self.call_log is not None:
            self.call_log.append("vault.resolve")
        self.calls.append(credential_ref)
        return self.credential


class FakeTerminalIO:
    def fileno(self) -> int:
        return 0

    def read_input(self, max_bytes: int) -> bytes:
        return b""

    def write_output(self, data: bytes) -> None:
        pass


class FakeBrokeredSession:
    def __init__(
        self,
        call_log: list[str] | None = None,
        relay_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.call_log = call_log
        self.relay_error = relay_error
        self.close_error = close_error
        self.relay_calls: list[TerminalIO] = []
        self.close_calls = 0
        self._closed = False

    def relay(self, terminal_io: TerminalIO) -> None:
        if self.call_log is not None:
            self.call_log.append("brokered_session.relay")
        self.relay_calls.append(terminal_io)
        if self.relay_error is not None:
            raise self.relay_error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.call_log is not None:
            self.call_log.append("brokered_session.close")
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeSessionBroker:
    def __init__(
        self,
        brokered_session: FakeBrokeredSession,
        call_log: list[str] | None = None,
        open_error: Exception | None = None,
    ) -> None:
        self.brokered_session = brokered_session
        self.call_log = call_log
        self.open_error = open_error
        self.calls: list[
            tuple[Target, PrivilegedAccount, BrokerCredential]
        ] = []

    def open_session(
        self,
        target: Target,
        privileged_account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> FakeBrokeredSession:
        if self.call_log is not None:
            self.call_log.append("session_broker.open_session")
        self.calls.append((target, privileged_account, credential))
        if self.open_error is not None:
            raise self.open_error
        return self.brokered_session


class FakeAuditRepository:
    def __init__(self, call_log: list[str] | None = None) -> None:
        self.call_log = call_log
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        if self.call_log is not None:
            self.call_log.append(f"audit.append:{event.event_type.value}")
        self.events.append(event)


class FakeTargetRepository:
    def __init__(
        self,
        targets: list[Target],
        call_log: list[str] | None = None,
    ) -> None:
        self.targets = targets
        self.call_log = call_log
        self.calls: list[str] = []

    def get(self, target_id: str) -> Target | None:
        if self.call_log is not None:
            self.call_log.append("target_repository.get")
        self.calls.append(target_id)
        return next(
            (target for target in self.targets if target.id == target_id),
            None,
        )


class FakePrivilegedAccountRepository:
    def __init__(
        self,
        accounts: list[PrivilegedAccount],
        call_log: list[str] | None = None,
    ) -> None:
        self.accounts = accounts
        self.call_log = call_log
        self.calls: list[str] = []

    def find_for_target(self, target_id: str) -> PrivilegedAccount | None:
        if self.call_log is not None:
            self.call_log.append("account_repository.find_for_target")
        self.calls.append(target_id)
        return next(
            (
                account
                for account in self.accounts
                if account.target_id == target_id
            ),
            None,
        )


class FixedClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


class FakeIdGenerator:
    def __init__(self) -> None:
        self.calls = 0

    def new_id(self) -> str:
        self.calls += 1
        return f"generated-{self.calls:03d}"
