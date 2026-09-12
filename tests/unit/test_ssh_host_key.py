import base64
import hashlib

import paramiko
import pytest

from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.ssh.errors import HostKeyMismatchError
from src.infrastructure.ssh.host_key import (
    calculate_sha256_fingerprint,
    verify_pinned_host_key,
)


def make_target(fingerprint: HostKeyFingerprint) -> Target:
    return Target(
        id="target-001",
        name="test-server",
        host="server.example.test",
        port=22,
        expected_host_key=fingerprint,
    )


def test_fingerprint_is_deterministic_and_starts_with_sha256():
    server_key = paramiko.RSAKey.generate(1024)

    first = calculate_sha256_fingerprint(server_key)
    second = calculate_sha256_fingerprint(server_key)

    assert first == second
    assert first.value.startswith("SHA256:")


def test_fingerprint_matches_openssh_sha256_format():
    server_key = paramiko.RSAKey.generate(1024)
    digest = hashlib.sha256(server_key.asbytes()).digest()
    expected = base64.b64encode(digest).decode("ascii").rstrip("=")

    fingerprint = calculate_sha256_fingerprint(server_key)

    assert fingerprint.value == f"SHA256:{expected}"
    assert not fingerprint.value.endswith("=")


def test_correct_pinned_host_key_is_accepted():
    server_key = paramiko.RSAKey.generate(1024)
    target = make_target(calculate_sha256_fingerprint(server_key))

    verify_pinned_host_key(target, server_key)


def test_incorrect_pinned_host_key_is_rejected():
    server_key = paramiko.RSAKey.generate(1024)
    target = make_target(HostKeyFingerprint("SHA256:incorrect"))

    with pytest.raises(
        HostKeyMismatchError,
        match="SSH host key mismatch for target target-001",
    ):
        verify_pinned_host_key(target, server_key)
