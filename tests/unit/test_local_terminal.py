import os

import pytest

import src.infrastructure.terminal.local_terminal_io as terminal_io_module
import src.infrastructure.terminal.terminal_mode as terminal_mode_module
from src.infrastructure.terminal.local_terminal_io import LocalTerminalIO
from src.infrastructure.terminal.terminal_mode import raw_terminal_mode
from src.ports.session_broker import TerminalIO


TERMINAL_MARKER = b"terminal-bytes\x00\xff"


def test_local_terminal_reads_binary_input_with_requested_bound():
    input_read_fd, input_write_fd = os.pipe()
    output_read_fd, output_write_fd = os.pipe()
    try:
        terminal: TerminalIO = LocalTerminalIO(
            input_fd=input_read_fd,
            output_fd=output_write_fd,
        )
        os.write(input_write_fd, TERMINAL_MARKER)

        first = terminal.read_input(4)
        second = terminal.read_input(len(TERMINAL_MARKER))

        assert first == TERMINAL_MARKER[:4]
        assert second == TERMINAL_MARKER[4:]
        assert isinstance(first, bytes)
        assert terminal.fileno() == input_read_fd
    finally:
        for file_descriptor in (
            input_read_fd,
            input_write_fd,
            output_read_fd,
            output_write_fd,
        ):
            os.close(file_descriptor)


def test_local_terminal_writes_exact_binary_output_without_decoding():
    input_read_fd, input_write_fd = os.pipe()
    output_read_fd, output_write_fd = os.pipe()
    try:
        terminal = LocalTerminalIO(
            input_fd=input_read_fd,
            output_fd=output_write_fd,
        )

        terminal.write_output(TERMINAL_MARKER)

        assert os.read(output_read_fd, len(TERMINAL_MARKER)) == TERMINAL_MARKER
        assert TERMINAL_MARKER.decode(errors="ignore") not in repr(terminal)
        assert set(terminal.__slots__) == {"_input_fd", "_output_fd"}
    finally:
        for file_descriptor in (
            input_read_fd,
            input_write_fd,
            output_read_fd,
            output_write_fd,
        ):
            os.close(file_descriptor)


def test_local_terminal_retries_partial_output_writes(
    monkeypatch: pytest.MonkeyPatch,
):
    chunks: list[bytes] = []

    def partial_write(file_descriptor: int, data: memoryview) -> int:
        assert file_descriptor == 9
        written = min(3, len(data))
        chunks.append(bytes(data[:written]))
        return written

    monkeypatch.setattr(terminal_io_module.os, "write", partial_write)
    terminal = LocalTerminalIO(input_fd=8, output_fd=9)

    terminal.write_output(TERMINAL_MARKER)

    assert b"".join(chunks) == TERMINAL_MARKER
    assert len(chunks) > 1


def test_raw_terminal_mode_restores_original_settings_on_normal_exit(
    monkeypatch: pytest.MonkeyPatch,
):
    original = ["original-settings"]
    events: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcgetattr",
        lambda fd: events.append(("get", fd)) or original,
    )
    monkeypatch.setattr(
        terminal_mode_module.tty,
        "setraw",
        lambda fd, when: events.append(("raw", fd, when)),
    )
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcsetattr",
        lambda fd, when, values: events.append(
            ("restore", fd, when, values)
        ),
    )

    with raw_terminal_mode(7):
        events.append(("operation",))

    assert events == [
        ("get", 7),
        ("raw", 7, terminal_mode_module.termios.TCSANOW),
        ("operation",),
        (
            "restore",
            7,
            terminal_mode_module.termios.TCSADRAIN,
            original,
        ),
    ]


def test_raw_terminal_mode_restores_when_wrapped_operation_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    original = ["original-settings"]
    restored: list[object] = []
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcgetattr",
        lambda fd: original,
    )
    monkeypatch.setattr(
        terminal_mode_module.tty,
        "setraw",
        lambda fd, when: None,
    )
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcsetattr",
        lambda fd, when, values: restored.append(values),
    )

    with pytest.raises(RuntimeError, match="controlled operation failure"):
        with raw_terminal_mode(7):
            raise RuntimeError("controlled operation failure")

    assert restored == [original]


def test_raw_terminal_mode_setup_failure_attempts_immediate_restoration(
    monkeypatch: pytest.MonkeyPatch,
):
    original = ["original-settings"]
    restored: list[tuple[int, int, object]] = []
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcgetattr",
        lambda fd: original,
    )

    def fail_setup(fd: int, when: int) -> None:
        raise RuntimeError("controlled setup failure")

    monkeypatch.setattr(terminal_mode_module.tty, "setraw", fail_setup)
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcsetattr",
        lambda fd, when, values: restored.append((fd, when, values)),
    )

    with pytest.raises(RuntimeError, match="controlled setup failure"):
        with raw_terminal_mode(7):
            pass

    assert restored == [
        (7, terminal_mode_module.termios.TCSANOW, original)
    ]


def test_nested_raw_terminal_modes_restore_each_captured_state(
    monkeypatch: pytest.MonkeyPatch,
):
    state = {"attributes": "original"}
    restorations: list[str] = []
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcgetattr",
        lambda fd: state["attributes"],
    )

    def enter_raw(fd: int, when: int) -> None:
        state["attributes"] = "raw"

    def restore(fd: int, when: int, attributes: str) -> None:
        restorations.append(attributes)
        state["attributes"] = attributes

    monkeypatch.setattr(terminal_mode_module.tty, "setraw", enter_raw)
    monkeypatch.setattr(
        terminal_mode_module.termios,
        "tcsetattr",
        restore,
    )

    with raw_terminal_mode(7):
        with raw_terminal_mode(7):
            assert state["attributes"] == "raw"
        assert state["attributes"] == "raw"

    assert restorations == ["raw", "original"]
    assert state["attributes"] == "original"
