from dataclasses import dataclass

import pytest

from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.ssh.errors import SshChannelError
import src.infrastructure.ssh.paramiko_session_broker as broker_module
from src.infrastructure.ssh.paramiko_session_broker import (
    ParamikoBrokeredSession,
    ParamikoSessionBroker,
)
from src.ports.session_broker import BrokerCredential
from tests.fakes.access_dependencies import FakeTerminalIO


CREDENTIAL_BYTES = b"temporary-broker-test-credential"


class FakeVerifiedConnection:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeInteractiveChannel:
    def __init__(self, close_error: Exception | None = None) -> None:
        self.close_error = close_error
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeConnector:
    def __init__(self, connection: FakeVerifiedConnection) -> None:
        self.connection = connection
        self.calls: list[tuple[str, str]] = []

    def connect(
        self,
        target: Target,
        account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> FakeVerifiedConnection:
        self.calls.append((target.id, account.id))
        return self.connection


@dataclass
class ChannelFactory:
    channel: FakeInteractiveChannel
    error: Exception | None = None
    calls: int = 0

    def open(self, connection: FakeVerifiedConnection) -> FakeInteractiveChannel:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.channel


def make_target() -> Target:
    return Target(
        id="target-001",
        name="test-server",
        host="server.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:test"),
    )


def make_account() -> PrivilegedAccount:
    return PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=CredentialRef("credential-001"),
    )


def install_channel_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory: ChannelFactory,
) -> None:
    monkeypatch.setattr(
        broker_module.InteractiveSshChannel,
        "open",
        factory.open,
    )


def test_open_session_composes_connector_and_channel_without_relaying(
    monkeypatch: pytest.MonkeyPatch,
):
    connection = FakeVerifiedConnection()
    channel = FakeInteractiveChannel()
    connector = FakeConnector(connection)
    factory = ChannelFactory(channel)
    install_channel_factory(monkeypatch, factory)
    relay_calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        broker_module,
        "relay_terminal",
        lambda channel, terminal: relay_calls.append((channel, terminal)),
    )
    broker = ParamikoSessionBroker(connector)

    brokered_session = broker.open_session(
        make_target(),
        make_account(),
        BrokerCredential(CREDENTIAL_BYTES),
    )

    assert isinstance(brokered_session, ParamikoBrokeredSession)
    assert connector.calls == [("target-001", "account-001")]
    assert factory.calls == 1
    assert relay_calls == []

    terminal_io = FakeTerminalIO()
    brokered_session.relay(terminal_io)
    assert relay_calls == [(channel, terminal_io)]
    brokered_session.close()


def test_channel_creation_failure_closes_verified_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    connection = FakeVerifiedConnection()
    channel = FakeInteractiveChannel()
    connector = FakeConnector(connection)
    factory = ChannelFactory(
        channel,
        error=SshChannelError("controlled channel failure"),
    )
    install_channel_factory(monkeypatch, factory)
    broker = ParamikoSessionBroker(connector)

    with pytest.raises(SshChannelError, match="controlled channel failure"):
        broker.open_session(
            make_target(),
            make_account(),
            BrokerCredential(CREDENTIAL_BYTES),
        )

    assert connection.close_calls == 1


def test_brokered_session_close_is_idempotent_and_closes_both_resources():
    connection = FakeVerifiedConnection()
    channel = FakeInteractiveChannel()
    brokered_session = ParamikoBrokeredSession(connection, channel)

    brokered_session.close()
    brokered_session.close()

    assert channel.close_calls == 1
    assert connection.close_calls == 1


def test_connection_closes_even_when_channel_close_fails():
    connection = FakeVerifiedConnection()
    channel = FakeInteractiveChannel(
        close_error=RuntimeError("controlled channel close failure")
    )
    brokered_session = ParamikoBrokeredSession(connection, channel)

    with pytest.raises(RuntimeError, match="controlled channel close failure"):
        brokered_session.close()

    assert channel.close_calls == 1
    assert connection.close_calls == 1


def test_adapter_and_brokered_session_do_not_retain_or_reveal_credential():
    credential_text = CREDENTIAL_BYTES.decode()
    connector = FakeConnector(FakeVerifiedConnection())
    broker = ParamikoSessionBroker(connector)
    brokered_session = ParamikoBrokeredSession(
        FakeVerifiedConnection(),
        FakeInteractiveChannel(),
    )

    assert credential_text not in repr(broker)
    assert credential_text not in repr(brokered_session)
    assert all("credential" not in name for name in broker.__slots__)
    assert all(
        "credential" not in name for name in brokered_session.__slots__
    )
