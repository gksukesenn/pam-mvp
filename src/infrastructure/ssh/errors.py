class SshConnectionError(Exception):
    """Raised when a verified SSH connection cannot be established."""


class HostKeyMismatchError(SshConnectionError):
    """Raised when the remote host key does not match the pinned key."""


class SshAuthenticationError(SshConnectionError):
    """Raised when SSH authentication fails safely."""
