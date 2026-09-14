import hashlib
import hmac
import json

GENESIS_MAC = b"\x00" * 32


def canonical_event_bytes(
    sequence_no: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    actor_user_id: str,
    target_id: str,
    session_id: str | None,
    result: str,
    reason_code: str | None,
) -> bytes:
    """Encode authenticated fields as ordered, compact UTF-8 JSON."""
    fields = [
        ["sequence_no", sequence_no],
        ["id", event_id],
        ["timestamp", timestamp],
        ["event_type", event_type],
        ["actor_user_id", actor_user_id],
        ["target_id", target_id],
        ["session_id", session_id],
        ["result", result],
        ["reason_code", reason_code],
    ]
    return json.dumps(
        fields,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def calculate_event_mac(
    key: bytes,
    canonical_event: bytes,
    previous_mac: bytes,
) -> bytes:
    return hmac.new(
        key,
        canonical_event + previous_mac,
        hashlib.sha256,
    ).digest()


def macs_match(actual: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(actual, expected)
