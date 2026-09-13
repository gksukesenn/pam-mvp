class ConfigStorageError(Exception):
    """Raised when non-secret configuration cannot be stored or loaded."""


class DuplicateTargetError(ConfigStorageError):
    """Raised when provisioning would overwrite an existing target ID."""


class DuplicatePrivilegedAccountError(ConfigStorageError):
    """Raised when provisioning would overwrite an existing account ID."""


class MalformedTargetError(ConfigStorageError):
    """Raised when persisted target configuration is malformed."""


class MalformedPrivilegedAccountError(ConfigStorageError):
    """Raised when persisted account configuration is malformed."""


class AmbiguousPrivilegedAccountError(ConfigStorageError):
    """Raised when a target has more than one configured account."""
