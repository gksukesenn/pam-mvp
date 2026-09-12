from pathlib import Path
import secrets

import pytest

from src.infrastructure.security.errors import KeyProviderError
from src.infrastructure.security.file_key_provider import FileKeyProvider


def write_key_file(
    path: Path,
    key: bytes,
    mode: int,
) -> None:
    path.write_bytes(key)
    path.chmod(mode)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_valid_key_is_loaded_with_restrictive_owner_mode(
    tmp_path: Path,
    mode: int,
):
    key = secrets.token_bytes(32)
    key_file = tmp_path / "master.key"
    write_key_file(key_file, key, mode)

    loaded = FileKeyProvider(key_file).get_key()

    assert loaded == key


def test_missing_key_file_fails_closed(tmp_path: Path):
    key_file = tmp_path / "missing.key"

    with pytest.raises(
        KeyProviderError,
        match="master key file does not exist",
    ):
        FileKeyProvider(key_file).get_key()

    assert not key_file.exists()


def test_wrong_length_key_fails_closed(tmp_path: Path):
    key_file = tmp_path / "master.key"
    write_key_file(key_file, secrets.token_bytes(31), 0o600)

    with pytest.raises(
        KeyProviderError,
        match="master key must be exactly 32 bytes",
    ):
        FileKeyProvider(key_file).get_key()


@pytest.mark.parametrize(
    "mode",
    [0o640, 0o620, 0o610, 0o604, 0o602, 0o601],
)
def test_group_or_world_permissions_are_rejected(
    tmp_path: Path,
    mode: int,
):
    key_file = tmp_path / "master.key"
    write_key_file(key_file, secrets.token_bytes(32), mode)

    with pytest.raises(
        KeyProviderError,
        match="master key file permissions are too broad",
    ):
        FileKeyProvider(key_file).get_key()


def test_provider_error_message_does_not_contain_key_bytes(tmp_path: Path):
    key = secrets.token_bytes(31)
    key_file = tmp_path / "master.key"
    write_key_file(key_file, key, 0o600)

    with pytest.raises(KeyProviderError) as captured:
        FileKeyProvider(key_file).get_key()

    message = str(captured.value)
    assert repr(key) not in message
    assert key.hex() not in message
