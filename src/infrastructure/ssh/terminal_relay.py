from collections.abc import Callable
from datetime import timedelta
import select
from time import monotonic as system_monotonic

from src.infrastructure.ssh.errors import SshChannelError
from src.infrastructure.ssh.interactive_channel import InteractiveSshChannel
from src.ports.session_broker import RelayOutcome, TerminalIO


def relay_terminal(
    channel: InteractiveSshChannel,
    terminal: TerminalIO,
    max_duration: timedelta,
    max_bytes: int = 32 * 1024,
    monotonic: Callable[[], float] = system_monotonic,
) -> RelayOutcome:
    """Relay binary chunks with a total-duration, not idle, timeout."""
    if max_duration <= timedelta(0):
        raise ValueError("max_duration must be positive")

    deadline = monotonic() + max_duration.total_seconds()
    try:
        while not channel.is_closed:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return RelayOutcome.MAX_DURATION_EXCEEDED

            readable, _, _ = select.select(
                [terminal, channel],
                [],
                [],
                remaining,
            )

            if monotonic() >= deadline:
                return RelayOutcome.MAX_DURATION_EXCEEDED

            if not readable:
                continue

            if channel in readable:
                remote_data = channel.receive(max_bytes)
                if not remote_data:
                    return RelayOutcome.COMPLETED
                terminal.write_output(remote_data)

            if terminal in readable:
                local_data = terminal.read_input(max_bytes)
                if not local_data:
                    return RelayOutcome.COMPLETED
                channel.send(local_data)
        return RelayOutcome.COMPLETED
    except Exception:
        raise SshChannelError("interactive terminal relay failed") from None
    finally:
        channel.close()
