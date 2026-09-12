from dataclasses import FrozenInstanceError

import pytest

from src.domain.target import HostKeyFingerprint, Target


def test_host_key_fingerprint_accepts_sha256():
    fingerprint = HostKeyFingerprint(
        "SHA256:abc123"
    )

    assert fingerprint.value == "SHA256:abc123"


def test_host_key_fingerprint_rejects_invalid_format():
    with pytest.raises(
        ValueError,
        match="SSH host key fingerprint",
    ):
        HostKeyFingerprint("abc123")


def test_host_key_fingerprint_is_immutable():
    fingerprint = HostKeyFingerprint("SHA256:abc123")

    with pytest.raises(FrozenInstanceError):
        fingerprint.value = "SHA256:different"


def test_target_can_be_created():
    fingerprint = HostKeyFingerprint(
        "SHA256:abc123"
    )

    target = Target(
        id="target-001",
        name="linux-server-1",
        host="server.example.test",
        port=22,
        expected_host_key=fingerprint,
    )

    assert target.id == "target-001"
    assert target.name == "linux-server-1"
    assert target.host == "server.example.test"
    assert target.port == 22
    assert target.expected_host_key == fingerprint
    assert target.enabled is True


def test_target_rejects_invalid_port():
    with pytest.raises(
        ValueError,
        match="target port must be between 1 and 65535",
    ):
        Target(
            id="target-001",
            name="linux-server-1",
            host="192.168.122.10",
            port=70000,
            expected_host_key=HostKeyFingerprint(
                "SHA256:abc123"
            ),
        )
