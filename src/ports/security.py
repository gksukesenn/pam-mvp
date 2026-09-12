from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EncryptedSecret:
    version: int
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 12:
            raise ValueError("nonce must be exactly 12 bytes")
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise ValueError("ciphertext cannot be empty")


class KeyProvider(Protocol):
    def get_key(self) -> bytes: ...


class SecretCipher(Protocol):
    def encrypt(self, plaintext: bytes) -> EncryptedSecret: ...

    def decrypt(self, encrypted: EncryptedSecret) -> bytes: ...
