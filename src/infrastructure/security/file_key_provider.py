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
        try:
            with self._key_file.open("rb") as key_stream:
                mode = stat.S_IMODE(os.fstat(key_stream.fileno()).st_mode)
                if mode & self.FORBIDDEN_PERMISSION_BITS:
                    raise KeyProviderError(
                        "master key file permissions are too broad"
                    )
                key = key_stream.read()
        except FileNotFoundError as error:
            raise KeyProviderError("master key file does not exist") from error
        except KeyProviderError:
            raise
        except OSError as error:
            raise KeyProviderError("master key file could not be read") from error

        if len(key) != self.KEY_SIZE:
            raise KeyProviderError("master key must be exactly 32 bytes")
        return key
