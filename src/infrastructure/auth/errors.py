class UserAuthStorageError(Exception):
    """Raised when local PAM-user authentication storage fails."""


class DuplicateUserIdError(UserAuthStorageError):
    """Raised when provisioning would reuse a PAM user ID."""


class DuplicateUsernameError(UserAuthStorageError):
    """Raised when provisioning would reuse a PAM username."""


class MalformedUserAuthError(UserAuthStorageError):
    """Raised when persisted PAM-user authentication data is malformed."""


class UnsupportedUserAuthSchemaError(UserAuthStorageError):
    """Raised when an auth database has an unsupported schema."""


class PasswordHashingError(Exception):
    """Raised when a PAM password cannot be hashed safely."""
