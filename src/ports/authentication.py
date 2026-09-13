from dataclasses import dataclass
from typing import Protocol

from src.domain.user import User


@dataclass(frozen=True, repr=False)
class StoredUserAuthentication:
    """A local user and its encoded one-way password hash."""

    user: User
    password_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.user, User):
            raise TypeError("stored authentication user is invalid")
        if type(self.password_hash) is not str or not self.password_hash:
            raise ValueError("stored password hash is invalid")

    def __repr__(self) -> str:
        return (
            "StoredUserAuthentication("
            f"user={self.user!r}, password_hash=<redacted>)"
        )


class UserAuthenticationRepository(Protocol):
    def find_by_username(
        self,
        username: str,
    ) -> StoredUserAuthentication | None: ...


class PasswordHasher(Protocol):
    def hash_password(self, password: str) -> str: ...

    def verify(self, password: str, encoded_hash: str) -> bool: ...
