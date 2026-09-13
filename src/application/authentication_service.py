"""Local PAM-user authentication.

Passwords are accepted as ``str`` and exist briefly in process memory. Python
cannot guarantee deterministic zeroization, and a fully compromised PAM host
is outside this MVP's threat boundary. The dummy verification removes the
obvious unknown-user fast path but does not promise timing indistinguishability.
Brute-force controls belong at a future outer application boundary.

The existing audit event schema requires an authenticated actor and a target,
so it cannot honestly represent pre-authentication attempts or targetless login
success. Authentication audit is therefore deferred until that schema is
extended rather than recording invented user or target identifiers.
"""

import secrets

from src.domain.authentication import AuthenticatedPrincipal
from src.ports.authentication import (
    PasswordHasher,
    UserAuthenticationRepository,
)


class AuthenticationFailedError(Exception):
    """Public, account-state-neutral PAM authentication failure."""


class AuthenticationService:
    """Authenticate a local PAM user without performing authorization."""

    __slots__ = ("_password_hasher", "_repository", "_dummy_hash")

    def __init__(
        self,
        repository: UserAuthenticationRepository,
        password_hasher: PasswordHasher,
    ) -> None:
        self._repository = repository
        self._password_hasher = password_hasher
        self._dummy_hash = password_hasher.hash_password(
            secrets.token_urlsafe(32)
        )

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> AuthenticatedPrincipal:
        try:
            stored_authentication = self._repository.find_by_username(username)
        except Exception:
            self._verify_dummy(password)
            raise AuthenticationFailedError("authentication failed") from None

        encoded_hash = (
            self._dummy_hash
            if stored_authentication is None
            else stored_authentication.password_hash
        )
        try:
            password_matches = self._password_hasher.verify(
                password,
                encoded_hash,
            )
        except Exception:
            raise AuthenticationFailedError("authentication failed") from None

        if (
            stored_authentication is None
            or stored_authentication.user.is_active is not True
            or password_matches is not True
        ):
            raise AuthenticationFailedError("authentication failed")

        try:
            return AuthenticatedPrincipal(
                user_id=stored_authentication.user.id,
                username=stored_authentication.user.username,
            )
        except (TypeError, ValueError):
            raise AuthenticationFailedError("authentication failed") from None

    def _verify_dummy(self, password: str) -> None:
        try:
            self._password_hasher.verify(password, self._dummy_hash)
        except Exception:
            pass
