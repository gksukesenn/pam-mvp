import base64
import hashlib
import hmac

import paramiko

from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.ssh.errors import HostKeyMismatchError


def calculate_sha256_fingerprint(
    server_key: paramiko.PKey,
) -> HostKeyFingerprint:
    digest = hashlib.sha256(server_key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return HostKeyFingerprint(f"SHA256:{encoded}")


def verify_pinned_host_key(
    target: Target,
    server_key: paramiko.PKey,
) -> None:
    actual = calculate_sha256_fingerprint(server_key)
    if not hmac.compare_digest(
        actual.value,
        target.expected_host_key.value,
    ):
        raise HostKeyMismatchError(
            f"SSH host key mismatch for target {target.id}"
        )
