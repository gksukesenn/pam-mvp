from argon2 import PasswordHasher as Argon2LibraryPasswordHasher
from argon2.exceptions import VerificationError

from src.infrastructure.auth.errors import PasswordHashingError


class Argon2PasswordHasher:
    """Argon2id password hashing using argon2-cffi's current defaults."""

    __slots__ = ("_hasher",)

    def __init__(self) -> None:
        self._hasher = Argon2LibraryPasswordHasher()

    def hash_password(self, password: str) -> str:
        if type(password) is not str:
            raise PasswordHashingError("password could not be hashed")
        try:
            return self._hasher.hash(password)
        except Exception:
            raise PasswordHashingError("password could not be hashed") from None

    def verify(self, password: str, encoded_hash: str) -> bool:
        if type(password) is not str or type(encoded_hash) is not str:
            return False
        try:
            return self._hasher.verify(encoded_hash, password)
        except (VerificationError, ValueError, TypeError):
            return False
