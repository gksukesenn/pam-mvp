import errno
import os
import stat
from pathlib import Path

from src.infrastructure.security.errors import KeyProviderError


class FileKeyProvider:
    KEY_SIZE = 32
    FORBIDDEN_PERMISSION_BITS = stat.S_IRWXG | stat.S_IRWXO

    def __init__(self, key_file: Path) -> None:
        self._key_file = key_file

    def get_key(self) -> bytes:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self._key_file,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK,
            )
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise KeyProviderError(
                    "master key path must identify a regular file"
                )
            mode = stat.S_IMODE(file_stat.st_mode)
            if mode & self.FORBIDDEN_PERMISSION_BITS:
                raise KeyProviderError(
                    "master key file permissions are too broad"
                )
            key = self._read_key(descriptor)
        except FileNotFoundError as error:
            raise KeyProviderError("master key file does not exist") from error
        except KeyProviderError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise KeyProviderError(
                    "master key path must identify a regular file"
                ) from None
            raise KeyProviderError(
                "master key file could not be read"
            ) from error
        except (TypeError, ValueError) as error:
            raise KeyProviderError(
                "master key file could not be read"
            ) from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        if len(key) != self.KEY_SIZE:
            raise KeyProviderError("master key must be exactly 32 bytes")
        return key

    @classmethod
    def _read_key(cls, descriptor: int) -> bytes:
        chunks: list[bytes] = []
        remaining = cls.KEY_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
