from datetime import UTC, datetime
from uuid import uuid4


class SystemClock:
    """Production UTC clock."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)


class UuidIdGenerator:
    """Production UUID4 string identifier generator."""

    __slots__ = ()

    def new_id(self) -> str:
        return str(uuid4())
