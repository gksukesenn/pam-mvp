from datetime import UTC
from uuid import UUID

from src.infrastructure.runtime import SystemClock, UuidIdGenerator
from src.ports.access_dependencies import Clock, IdGenerator


def test_system_clock_returns_timezone_aware_utc_time():
    clock: Clock = SystemClock()

    current = clock.now()

    assert current.tzinfo is UTC
    assert current.utcoffset() is not None


def test_uuid_id_generator_returns_unique_uuid4_strings():
    generator: IdGenerator = UuidIdGenerator()

    first = generator.new_id()
    second = generator.new_id()

    assert first != second
    assert UUID(first).version == 4
    assert UUID(second).version == 4
