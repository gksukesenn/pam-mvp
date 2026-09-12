from datetime import timedelta

from src.domain.privileged_account import PrivilegedAccount
from src.domain.target import Target
from src.infrastructure.ssh.errors import SshChannelError
from src.infrastructure.ssh.interactive_channel import InteractiveSshChannel
from src.infrastructure.ssh.paramiko_connection import (
    ParamikoSshConnector,
    VerifiedSshConnection,
)
from src.infrastructure.ssh.terminal_relay import relay_terminal
from src.ports.session_broker import (
    BrokerCredential,
    RelayOutcome,
    TerminalIO,
)


class ParamikoBrokeredSession:
    __slots__ = ("_connection", "_channel", "_closed")

    def __init__(
        self,
        connection: VerifiedSshConnection,
        channel: InteractiveSshChannel,
    ) -> None:
        self._connection = connection
        self._channel = channel
        self._closed = False

    def relay(
        self,
        terminal_io: TerminalIO,
        max_duration: timedelta,
    ) -> RelayOutcome:
        if self._closed:
            raise SshChannelError("brokered SSH session is closed")
        return relay_terminal(
            self._channel,
            terminal_io,
            max_duration=max_duration,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._channel.close()
        finally:
            self._connection.close()

    def __repr__(self) -> str:
        return f"ParamikoBrokeredSession(closed={self._closed})"


class ParamikoSessionBroker:
    __slots__ = ("_connector",)

    def __init__(self, connector: ParamikoSshConnector | None = None) -> None:
        self._connector = connector or ParamikoSshConnector()

    def open_session(
        self,
        target: Target,
        privileged_account: PrivilegedAccount,
        credential: BrokerCredential,
    ) -> ParamikoBrokeredSession:
        connection = self._connector.connect(
            target,
            privileged_account,
            credential,
        )
        try:
            channel = InteractiveSshChannel.open(connection)
        except Exception:
            try:
                connection.close()
            except Exception:
                pass
            raise

        return ParamikoBrokeredSession(connection, channel)

    def __repr__(self) -> str:
        return "ParamikoSessionBroker()"
