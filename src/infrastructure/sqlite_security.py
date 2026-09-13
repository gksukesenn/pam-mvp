"""Filesystem protection shared by SQLite infrastructure adapters."""

import os
from pathlib import Path
import stat


DATABASE_FILE_MODE = 0o600


class DatabasePermissionError(Exception):
    """Raised when a SQLite file cannot be protected for its owner."""


def ensure_owner_only_database_file(database_path: Path) -> None:
    """Create or tighten one regular database file to exactly mode 0600."""

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                database_path,
                flags | os.O_CREAT | os.O_EXCL,
                DATABASE_FILE_MODE,
            )
        except FileExistsError:
            descriptor = os.open(database_path, flags)

        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise DatabasePermissionError(
                "database path must identify a regular file"
            )
        os.fchmod(descriptor, DATABASE_FILE_MODE)
        secured_mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        if secured_mode != DATABASE_FILE_MODE:
            raise DatabasePermissionError(
                "database file permissions could not be secured"
            )
    except DatabasePermissionError:
        raise
    except (OSError, TypeError, ValueError):
        raise DatabasePermissionError(
            "database file permissions could not be secured"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
