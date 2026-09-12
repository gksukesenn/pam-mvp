class VaultError(Exception):
    """Raised when a credential cannot be stored or resolved safely."""


class DuplicateCredentialError(VaultError):
    """Raised when provisioning would overwrite an existing credential."""
