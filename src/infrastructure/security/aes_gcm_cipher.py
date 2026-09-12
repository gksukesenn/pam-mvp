import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.infrastructure.security.errors import SecretCipherError
from src.ports.security import EncryptedSecret


class AesGcmSecretCipher:
    KEY_SIZE = 32
    NONCE_SIZE = 12
    VERSION = 1

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != self.KEY_SIZE:
            raise SecretCipherError("AES-GCM key must be exactly 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> EncryptedSecret:
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, None)
        return EncryptedSecret(
            version=self.VERSION,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt(self, encrypted: EncryptedSecret) -> bytes:
        if encrypted.version != self.VERSION:
            raise SecretCipherError("unsupported encrypted secret version")

        try:
            return self._cipher.decrypt(
                encrypted.nonce,
                encrypted.ciphertext,
                None,
            )
        except InvalidTag as error:
            raise SecretCipherError("secret authentication failed") from error
