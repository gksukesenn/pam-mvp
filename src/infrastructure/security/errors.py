class SecurityError(Exception):
    """Base error for secret-protection failures."""


class SecretCipherError(SecurityError):
    """Raised when secret encryption or decryption cannot complete safely."""


class KeyProviderError(SecurityError):
    """Raised when a valid master key cannot be loaded safely."""
