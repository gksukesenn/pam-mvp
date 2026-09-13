class PolicyStorageError(Exception):
    """Raised when access policies cannot be stored or loaded safely."""


class DuplicatePolicyError(PolicyStorageError):
    """Raised when provisioning would overwrite an existing policy ID."""


class MalformedPolicyError(PolicyStorageError):
    """Raised when a matching persisted policy cannot be reconstructed."""
