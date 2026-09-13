import os


class LocalTerminalIO:
    """Binary local stdin/stdout adapter for the Linux terminal."""

    __slots__ = ("_input_fd", "_output_fd")

    def __init__(self, input_fd: int = 0, output_fd: int = 1) -> None:
        if type(input_fd) is not int or input_fd < 0:
            raise ValueError("input file descriptor must be nonnegative")
        if type(output_fd) is not int or output_fd < 0:
            raise ValueError("output file descriptor must be nonnegative")
        self._input_fd = input_fd
        self._output_fd = output_fd

    def fileno(self) -> int:
        return self._input_fd

    def read_input(self, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        return os.read(self._input_fd, max_bytes)

    def write_output(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("terminal output must be bytes")
        remaining = memoryview(data)
        while remaining:
            written = os.write(self._output_fd, remaining)
            if written == 0:
                raise OSError("terminal output write made no progress")
            remaining = remaining[written:]

    def __repr__(self) -> str:
        return "LocalTerminalIO()"
