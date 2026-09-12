"""Persistent audit infrastructure for the MVP.

Retention is intentionally deferred. The audit database grows indefinitely
until a later phase defines an operational retention policy.

The local HMAC chain is tamper-evident, not tamper-proof. Without an externally
trusted chain-head anchor, removal of a valid suffix cannot be detected.
"""
