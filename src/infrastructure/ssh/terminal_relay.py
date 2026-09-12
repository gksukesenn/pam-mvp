import select
from typing import Protocol

from src.infrastructure.ssh.errors import SshChannelError
from src.infrastructure.ssh.interactive_channel import InteractiveSshChannel


class TerminalIO(Protocol):
    def fileno(self) -> int: ...

    def read_input(self, max_bytes: int) -> bytes: ...

    def write_output(self, data: bytes) -> None: ...


def relay_terminal(
    channel: InteractiveSshChannel,
    terminal: TerminalIO,
    max_bytes: int = 32 * 1024,
) -> None:
    """Relay bounded binary chunks using Linux-compatible file descriptors."""
    try:
        while not channel.is_closed:
            readable, _, _ = select.select(
                [terminal, channel],
                [],
                [],
            )

            if channel in readable:
                remote_data = channel.receive(max_bytes)
                if not remote_data:
                    break
                terminal.write_output(remote_data)

            if terminal in readable:
                local_data = terminal.read_input(max_bytes)
                if not local_data:
                    break
                channel.send(local_data)
    except Exception:
        raise SshChannelError("interactive terminal relay failed") from None
    finally:
        channel.close()
