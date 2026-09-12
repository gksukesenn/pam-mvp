from datetime import timedelta
import inspect
from pathlib import Path
import re

import pytest

from src.infrastructure.ssh.errors import SshChannelError
from src.infrastructure.ssh.interactive_channel import InteractiveSshChannel
from src.infrastructure.ssh.paramiko_connection import VerifiedSshConnection
import src.infrastructure.ssh.terminal_relay as relay_module
from src.infrastructure.ssh.terminal_relay import relay_terminal
from src.ports.session_broker import RelayOutcome


TERMINAL_CONTENT = b"terminal-test-content\x00\xff"
MAX_DURATION = timedelta(seconds=10)


class FakeMonotonic:
    def __init__(self, values: list[float]) -> None:
        self.values = values
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.values.pop(0)


class FakeSocket:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeChannel:
    def __init__(
        self,
        events: list[str] | None = None,
        *,
        pty_error: Exception | None = None,
        shell_error: Exception | None = None,
        send_error: Exception | None = None,
        received_chunks: list[bytes] | None = None,
    ) -> None:
        self.events = [] if events is None else events
        self.pty_error = pty_error
        self.shell_error = shell_error
        self.send_error = send_error
        self.received_chunks = (
            [] if received_chunks is None else received_chunks
        )
        self.sent_chunks: list[bytes] = []
        self.receive_sizes: list[int] = []
        self.close_calls = 0
        self.closed = False

    def get_pty(self, term: str, width: int, height: int) -> None:
        self.events.append(f"get_pty:{term}:{width}:{height}")
        if self.pty_error is not None:
            raise self.pty_error

    def invoke_shell(self) -> None:
        self.events.append("invoke_shell")
        if self.shell_error is not None:
            raise self.shell_error

    def fileno(self) -> int:
        return 101

    def sendall(self, data: bytes) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.sent_chunks.append(data)

    def recv(self, max_bytes: int) -> bytes:
        self.receive_sizes.append(max_bytes)
        return self.received_chunks.pop(0)

    def close(self) -> None:
        self.events.append("channel_close")
        self.close_calls += 1
        self.closed = True


class FakeTransport:
    def __init__(
        self,
        channel: FakeChannel,
        events: list[str],
        open_error: Exception | None = None,
    ) -> None:
        self.channel = channel
        self.events = events
        self.open_error = open_error
        self.close_calls = 0

    def open_session(self) -> FakeChannel:
        self.events.append("open_session")
        if self.open_error is not None:
            raise self.open_error
        return self.channel

    def close(self) -> None:
        self.close_calls += 1


class FakeTerminalIO:
    def __init__(self, input_chunks: list[bytes] | None = None) -> None:
        self.input_chunks = [] if input_chunks is None else input_chunks
        self.output_chunks: list[bytes] = []
        self.read_sizes: list[int] = []

    def fileno(self) -> int:
        return 102

    def read_input(self, max_bytes: int) -> bytes:
        self.read_sizes.append(max_bytes)
        return self.input_chunks.pop(0)

    def write_output(self, data: bytes) -> None:
        self.output_chunks.append(data)


def make_connection(
    channel: FakeChannel,
    events: list[str],
    open_error: Exception | None = None,
) -> tuple[VerifiedSshConnection, FakeTransport, FakeSocket]:
    transport = FakeTransport(channel, events, open_error)
    connection_socket = FakeSocket()
    connection = VerifiedSshConnection(transport, connection_socket)
    return connection, transport, connection_socket


def install_select_plan(
    monkeypatch: pytest.MonkeyPatch,
    plan: list[str],
    channel: InteractiveSshChannel,
    terminal: FakeTerminalIO,
    timeouts: list[float] | None = None,
) -> None:
    def controlled_select(
        readers: list[object],
        writers: list[object],
        errors: list[object],
        timeout: float,
    ) -> tuple[list[object], list[object], list[object]]:
        assert readers == [terminal, channel]
        assert writers == []
        assert errors == []
        if timeouts is not None:
            timeouts.append(timeout)
        ready = plan.pop(0)
        if ready == "timeout":
            return [], [], []
        endpoint = channel if ready == "remote" else terminal
        return [endpoint], [], []

    monkeypatch.setattr(relay_module.select, "select", controlled_select)


def test_channel_opening_orders_session_pty_then_shell():
    events: list[str] = []
    raw_channel = FakeChannel(events)
    connection, transport, connection_socket = make_connection(
        raw_channel,
        events,
    )

    channel = InteractiveSshChannel.open(connection)

    assert events == [
        "open_session",
        "get_pty:xterm:80:24",
        "invoke_shell",
    ]
    assert isinstance(channel, InteractiveSshChannel)
    channel.close()
    assert transport.close_calls == 0
    assert connection_socket.close_calls == 0
    connection.close()


def test_session_open_failure_raises_project_error():
    events: list[str] = []
    raw_channel = FakeChannel(events)
    connection, _, _ = make_connection(
        raw_channel,
        events,
        open_error=RuntimeError("controlled open failure"),
    )

    with pytest.raises(
        SshChannelError,
        match="SSH session channel could not be opened",
    ):
        InteractiveSshChannel.open(connection)

    assert events == ["open_session"]
    connection.close()


def test_pty_failure_closes_channel_and_does_not_invoke_shell():
    events: list[str] = []
    raw_channel = FakeChannel(
        events,
        pty_error=RuntimeError("controlled PTY failure"),
    )
    connection, _, _ = make_connection(raw_channel, events)

    with pytest.raises(SshChannelError, match="SSH PTY request failed"):
        InteractiveSshChannel.open(connection)

    assert events == [
        "open_session",
        "get_pty:xterm:80:24",
        "channel_close",
    ]
    assert "invoke_shell" not in events
    assert raw_channel.close_calls == 1
    connection.close()


def test_shell_failure_closes_channel():
    events: list[str] = []
    raw_channel = FakeChannel(
        events,
        shell_error=RuntimeError("controlled shell failure"),
    )
    connection, _, _ = make_connection(raw_channel, events)

    with pytest.raises(SshChannelError, match="SSH shell request failed"):
        InteractiveSshChannel.open(connection)

    assert events == [
        "open_session",
        "get_pty:xterm:80:24",
        "invoke_shell",
        "channel_close",
    ]
    assert raw_channel.close_calls == 1
    connection.close()


def test_channel_close_is_explicit_and_idempotent():
    raw_channel = FakeChannel()
    channel = InteractiveSshChannel(raw_channel)

    channel.close()
    channel.close()

    assert raw_channel.close_calls == 1


def test_channel_repr_exposes_no_terminal_content_or_credential():
    raw_channel = FakeChannel(received_chunks=[TERMINAL_CONTENT])
    channel = InteractiveSshChannel(raw_channel)

    representation = repr(channel)

    assert TERMINAL_CONTENT.decode("latin-1") not in representation
    assert "credential" not in representation.lower()
    assert all("credential" not in name for name in channel.__slots__)
    channel.close()


def test_relay_sends_local_input_to_remote_and_stops_on_local_eof(
    monkeypatch: pytest.MonkeyPatch,
):
    raw_channel = FakeChannel()
    channel = InteractiveSshChannel(raw_channel)
    terminal = FakeTerminalIO([TERMINAL_CONTENT, b""])
    install_select_plan(
        monkeypatch,
        ["local", "local"],
        channel,
        terminal,
    )
    monotonic = FakeMonotonic([0, 0, 1, 1, 2])

    outcome = relay_terminal(
        channel,
        terminal,
        max_duration=MAX_DURATION,
        monotonic=monotonic,
    )

    assert outcome is RelayOutcome.COMPLETED
    assert raw_channel.sent_chunks == [TERMINAL_CONTENT]
    assert terminal.read_sizes == [32 * 1024, 32 * 1024]
    assert raw_channel.close_calls == 1


def test_relay_writes_remote_bytes_and_stops_on_remote_eof(
    monkeypatch: pytest.MonkeyPatch,
):
    raw_channel = FakeChannel(
        received_chunks=[TERMINAL_CONTENT, b""],
    )
    channel = InteractiveSshChannel(raw_channel)
    terminal = FakeTerminalIO()
    install_select_plan(
        monkeypatch,
        ["remote", "remote"],
        channel,
        terminal,
    )
    monotonic = FakeMonotonic([0, 0, 1, 1, 2])

    outcome = relay_terminal(
        channel,
        terminal,
        max_duration=MAX_DURATION,
        monotonic=monotonic,
    )

    assert outcome is RelayOutcome.COMPLETED
    assert terminal.output_chunks == [TERMINAL_CONTENT]
    assert raw_channel.receive_sizes == [32 * 1024, 32 * 1024]
    assert raw_channel.close_calls == 1


def test_relay_closes_channel_when_io_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    raw_channel = FakeChannel(
        send_error=RuntimeError("controlled send failure"),
    )
    channel = InteractiveSshChannel(raw_channel)
    terminal = FakeTerminalIO([TERMINAL_CONTENT])
    install_select_plan(monkeypatch, ["local"], channel, terminal)
    monotonic = FakeMonotonic([0, 0, 1])

    with pytest.raises(
        SshChannelError,
        match="interactive terminal relay failed",
    ):
        relay_terminal(
            channel,
            terminal,
            max_duration=MAX_DURATION,
            monotonic=monotonic,
        )

    assert raw_channel.close_calls == 1


def test_relay_times_out_without_io_using_remaining_select_timeout(
    monkeypatch: pytest.MonkeyPatch,
):
    raw_channel = FakeChannel()
    channel = InteractiveSshChannel(raw_channel)
    terminal = FakeTerminalIO()
    select_timeouts: list[float] = []
    install_select_plan(
        monkeypatch,
        ["timeout"],
        channel,
        terminal,
        select_timeouts,
    )
    monotonic = FakeMonotonic([100, 102, 110])

    outcome = relay_terminal(
        channel,
        terminal,
        max_duration=MAX_DURATION,
        monotonic=monotonic,
    )

    assert outcome is RelayOutcome.MAX_DURATION_EXCEEDED
    assert select_timeouts == [8]
    assert monotonic.calls == 3
    assert raw_channel.close_calls == 1
    assert raw_channel.sent_chunks == []
    assert terminal.output_chunks == []


def test_terminal_activity_does_not_reset_maximum_duration(
    monkeypatch: pytest.MonkeyPatch,
):
    raw_channel = FakeChannel()
    channel = InteractiveSshChannel(raw_channel)
    terminal = FakeTerminalIO([TERMINAL_CONTENT])
    select_timeouts: list[float] = []
    install_select_plan(
        monkeypatch,
        ["local"],
        channel,
        terminal,
        select_timeouts,
    )
    monotonic = FakeMonotonic([0, 0, 1, 10])

    outcome = relay_terminal(
        channel,
        terminal,
        max_duration=MAX_DURATION,
        monotonic=monotonic,
    )

    assert outcome is RelayOutcome.MAX_DURATION_EXCEEDED
    assert raw_channel.sent_chunks == [TERMINAL_CONTENT]
    assert select_timeouts == [10]
    assert raw_channel.close_calls == 1


def test_relay_requires_duration_and_uses_no_wall_clock():
    parameter = inspect.signature(relay_terminal).parameters[
        "max_duration"
    ]
    source = inspect.getsource(relay_module)

    assert parameter.default is inspect.Parameter.empty
    assert "datetime.now" not in source
    assert "datetime.utcnow" not in source


def test_ssh_pty_source_has_no_content_logging_recording_or_scope_creep():
    project_root = Path(__file__).parents[2]
    source = "\n".join(
        path.read_text()
        for path in (project_root / "src/infrastructure/ssh").glob("*.py")
    )

    assert re.search(r"\bprint\s*\(", source) is None
    assert "logging" not in source
    assert "transcript" not in source
    assert "recording" not in source
    assert "command_filter" not in source
    assert "AutoAddPolicy" not in source
    assert "set_missing_host_key_policy" not in source
    assert "forward_agent" not in source
    assert "request_port_forward" not in source
    assert "open_sftp" not in source
