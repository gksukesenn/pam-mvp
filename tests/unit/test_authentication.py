from dataclasses import FrozenInstanceError, fields

import pytest

from src.application.authentication_service import (
    AuthenticationFailedError,
    AuthenticationService,
)
from src.domain.authentication import AuthenticatedPrincipal
from src.domain.user import User
from src.ports.authentication import StoredUserAuthentication

PASSWORD_MARKER = "PAM-LOGIN-PLAINTEXT-MARKER"  # pragma: allowlist secret


class FakeUserAuthenticationRepository:
    def __init__(
        self,
        stored_authentication: StoredUserAuthentication | None,
        error: Exception | None = None,
    ) -> None:
        self.stored_authentication = stored_authentication
        self.error = error
        self.usernames: list[str] = []

    def find_by_username(
        self,
        username: str,
    ) -> StoredUserAuthentication | None:
        self.usernames.append(username)
        if self.error is not None:
            raise self.error
        if (
            self.stored_authentication is not None
            and self.stored_authentication.user.username == username
        ):
            return self.stored_authentication
        return None


class FakePasswordHasher:
    def __init__(self) -> None:
        self.verify_calls: list[tuple[str, str]] = []
        self.verify_error: Exception | None = None

    def hash_password(self, password: str) -> str:
        return "$argon2id$dummy-hash"

    def verify(self, password: str, encoded_hash: str) -> bool:
        self.verify_calls.append((password, encoded_hash))
        if self.verify_error is not None:
            raise self.verify_error
        return password == PASSWORD_MARKER and encoded_hash == "encoded-user-hash"


def make_stored_authentication(
    *,
    is_active: bool = True,
) -> StoredUserAuthentication:
    return StoredUserAuthentication(
        user=User(
            id="user-001",
            username="goksu",
            is_active=is_active,
        ),
        password_hash="encoded-user-hash",  # pragma: allowlist secret
    )


def make_service(
    stored_authentication: StoredUserAuthentication | None,
    *,
    repository_error: Exception | None = None,
) -> tuple[
    AuthenticationService,
    FakeUserAuthenticationRepository,
    FakePasswordHasher,
]:
    repository = FakeUserAuthenticationRepository(
        stored_authentication,
        repository_error,
    )
    password_hasher = FakePasswordHasher()
    service = AuthenticationService(repository, password_hasher)
    return service, repository, password_hasher


def test_authenticated_principal_is_immutable_nonsecret_identity():
    principal = AuthenticatedPrincipal(
        user_id="user-001",
        username="goksu",
    )

    assert fields(principal) == fields(AuthenticatedPrincipal)
    assert {field.name for field in fields(principal)} == {
        "user_id",
        "username",
    }
    assert PASSWORD_MARKER not in repr(principal)
    with pytest.raises(FrozenInstanceError):
        principal.user_id = "user-002"


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("user_id", " ", "principal user id cannot be empty"),
        ("username", "", "principal username cannot be empty"),
    ],
)
def test_authenticated_principal_rejects_blank_identifiers(
    field_name: str,
    value: str,
    message: str,
):
    values = {"user_id": "user-001", "username": "goksu"}
    values[field_name] = value

    with pytest.raises(ValueError, match=message):
        AuthenticatedPrincipal(**values)


def test_valid_active_user_authenticates_to_nonsecret_principal():
    service, repository, password_hasher = make_service(
        make_stored_authentication()
    )

    principal = service.authenticate("goksu", PASSWORD_MARKER)

    assert principal == AuthenticatedPrincipal(
        user_id="user-001",
        username="goksu",
    )
    assert repository.usernames == ["goksu"]
    assert password_hasher.verify_calls == [
        (PASSWORD_MARKER, "encoded-user-hash")
    ]
    assert PASSWORD_MARKER not in repr(service)
    assert PASSWORD_MARKER not in repr(repository)
    assert "encoded-user-hash" not in repr(principal)


@pytest.mark.parametrize(
    "stored_authentication",
    [make_stored_authentication(), None],
)
def test_wrong_password_and_unknown_username_have_same_public_failure(
    stored_authentication: StoredUserAuthentication | None,
):
    service, _, password_hasher = make_service(stored_authentication)
    username = "goksu" if stored_authentication is not None else "unknown"

    with pytest.raises(AuthenticationFailedError) as captured:
        service.authenticate(username, "wrong-password")

    assert str(captured.value) == "authentication failed"
    assert len(password_hasher.verify_calls) == 1
    if stored_authentication is None:
        assert password_hasher.verify_calls[0][1] == "$argon2id$dummy-hash"


def test_inactive_user_cannot_authenticate_even_with_correct_password():
    service, _, password_hasher = make_service(
        make_stored_authentication(is_active=False)
    )

    with pytest.raises(
        AuthenticationFailedError,
        match="^authentication failed$",
    ):
        service.authenticate("goksu", PASSWORD_MARKER)

    assert len(password_hasher.verify_calls) == 1


def test_repository_failure_fails_closed_and_runs_dummy_verification():
    service, _, password_hasher = make_service(
        None,
        repository_error=RuntimeError("controlled repository failure"),
    )

    with pytest.raises(
        AuthenticationFailedError,
        match="^authentication failed$",
    ):
        service.authenticate("goksu", PASSWORD_MARKER)

    assert password_hasher.verify_calls == [
        (PASSWORD_MARKER, "$argon2id$dummy-hash")
    ]


def test_password_hasher_failure_fails_closed_without_sensitive_error():
    service, _, password_hasher = make_service(make_stored_authentication())
    password_hasher.verify_error = RuntimeError("controlled hasher failure")

    with pytest.raises(AuthenticationFailedError) as captured:
        service.authenticate("goksu", PASSWORD_MARKER)

    assert str(captured.value) == "authentication failed"
    assert PASSWORD_MARKER not in repr(captured.value)
    assert "encoded-user-hash" not in repr(captured.value)
