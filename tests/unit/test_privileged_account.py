from dataclasses import FrozenInstanceError, fields

import pytest

from src.domain.privileged_account import CredentialRef, PrivilegedAccount


def test_credential_ref_can_be_created():
    credential_ref = CredentialRef(id="credential-001")

    assert credential_ref.id == "credential-001"


def test_credential_ref_rejects_blank_id():
    with pytest.raises(
        ValueError,
        match="credential reference id cannot be empty",
    ):
        CredentialRef(id="   ")


def test_credential_ref_is_immutable():
    credential_ref = CredentialRef(id="credential-001")

    with pytest.raises(FrozenInstanceError):
        credential_ref.id = "credential-002"


def test_privileged_account_can_be_created():
    credential_ref = CredentialRef(id="credential-001")

    account = PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=credential_ref,
    )

    assert account.id == "account-001"
    assert account.target_id == "target-001"
    assert account.username == "root"
    assert account.enabled is True


def test_privileged_account_rejects_blank_username():
    with pytest.raises(ValueError, match="username cannot be empty"):
        PrivilegedAccount(
            id="account-001",
            target_id="target-001",
            username="",
            credential_ref=CredentialRef(id="credential-001"),
        )


def test_privileged_account_contains_credential_ref():
    credential_ref = CredentialRef(id="credential-001")

    account = PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="root",
        credential_ref=credential_ref,
    )

    assert account.credential_ref is credential_ref


def test_privileged_account_exposes_no_plaintext_secret_field():
    field_names = {field.name for field in fields(PrivilegedAccount)}

    assert field_names == {
        "id",
        "target_id",
        "username",
        "credential_ref",
        "enabled",
    }
