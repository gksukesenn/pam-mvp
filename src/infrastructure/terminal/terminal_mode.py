from collections.abc import Iterator
from contextlib import contextmanager
import termios
import tty


@contextmanager
def raw_terminal_mode(file_descriptor: int) -> Iterator[None]:
    """Temporarily put one Linux terminal file descriptor in raw mode."""

    if type(file_descriptor) is not int or file_descriptor < 0:
        raise ValueError("terminal file descriptor must be nonnegative")

    original_attributes = termios.tcgetattr(file_descriptor)
    try:
        tty.setraw(file_descriptor, termios.TCSANOW)
    except BaseException:
        termios.tcsetattr(
            file_descriptor,
            termios.TCSANOW,
            original_attributes,
        )
        raise

    try:
        yield
    finally:
        termios.tcsetattr(
            file_descriptor,
            termios.TCSADRAIN,
            original_attributes,
        )
