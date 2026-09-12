import paramiko

from src.infrastructure.ssh.errors import SshChannelError
from src.infrastructure.ssh.paramiko_connection import VerifiedSshConnection


class InteractiveSshChannel:
    __slots__ = ("_channel", "_closed")

    def __init__(self, channel: paramiko.Channel) -> None:
        self._channel = channel
        self._closed = False

    @classmethod
    def open(
        cls,
        connection: VerifiedSshConnection,
        term: str = "xterm",
        width: int = 80,
        height: int = 24,
    ) -> "InteractiveSshChannel":
        try:
            channel = connection._open_session_channel()
        except Exception:
            raise SshChannelError(
                "SSH session channel could not be opened"
            ) from None

        try:
            channel.get_pty(term=term, width=width, height=height)
        except Exception:
            cls._close_partial_channel(channel)
            raise SshChannelError("SSH PTY request failed") from None

        try:
            channel.invoke_shell()
        except Exception:
            cls._close_partial_channel(channel)
            raise SshChannelError("SSH shell request failed") from None

        return cls(channel)

    @property
    def is_closed(self) -> bool:
        return self._closed or self._channel.closed

    def fileno(self) -> int:
        return self._channel.fileno()

    def send(self, data: bytes) -> None:
        self._channel.sendall(data)

    def receive(self, max_bytes: int) -> bytes:
        return self._channel.recv(max_bytes)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._channel.close()

    def __enter__(self) -> "InteractiveSshChannel":
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"InteractiveSshChannel(closed={self.is_closed})"

    @staticmethod
    def _close_partial_channel(channel: paramiko.Channel) -> None:
        try:
            channel.close()
        except Exception:
            pass
