from contextlib import closing
from dataclasses import fields
from pathlib import Path
import secrets
import sqlite3

import pytest

from src.domain.privileged_account import CredentialRef
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.vault.errors import (
    DuplicateCredentialError,
    VaultError,
)
from src.infrastructure.vault.sqlite_vault import SQLiteVault
from src.ports.access_dependencies import VaultPort
from src.ports.session_broker import BrokerCredential


PLAINTEXT_MARKER = b"PAM-PHASE-5B-PLAINTEXT-CREDENTIAL-DO-NOT-PERSIST"


def make_vault(
    tmp_path: Path,
    key: bytes | None = None,
) -> tuple[SQLiteVault, Path, bytes]:
    master_key = secrets.token_bytes(32) if key is None else key
    database_path = tmp_path / "vault.db"
    vault = SQLiteVault(
        database_path,
        AesGcmSecretCipher(master_key),
    )
    return vault, database_path, master_key


def read_credential_row(
    database_path: Path,
    credential_id: str,
) -> tuple[int, bytes, bytes] | None:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT encryption_version, nonce, ciphertext
            FROM vault_credentials
            WHERE id = ?
            """,
            (credential_id,),
        ).fetchone()


def update_credential_field(
    database_path: Path,
    field_name: str,
    value: object,
    credential_id: str,
) -> None:
    allowed_fields = {"encryption_version", "nonce", "ciphertext"}
    assert field_name in allowed_fields
    statement = {
        "encryption_version": (
            "UPDATE vault_credentials SET encryption_version = ? WHERE id = ?"
        ),
        "nonce": "UPDATE vault_credentials SET nonce = ? WHERE id = ?",
        "ciphertext": (
            "UPDATE vault_credentials SET ciphertext = ? WHERE id = ?"
        ),
    }[field_name]
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(statement, (value, credential_id))


def test_storing_credential_persists_only_encrypted_fields(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")

    vault.store(credential_ref, PLAINTEXT_MARKER)

    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(vault_credentials)"
            ).fetchall()
        ]
    row = read_credential_row(database_path, credential_ref.id)
    assert columns == [
        "id",
        "encryption_version",
        "nonce",
        "ciphertext",
    ]
    assert row is not None
    version, nonce, ciphertext = row
    assert version == 1
    assert len(nonce) == 12
    assert ciphertext
    assert ciphertext != PLAINTEXT_MARKER


def test_duplicate_credential_id_is_rejected(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)

    with pytest.raises(
        DuplicateCredentialError,
        match="credential id already exists",
    ):
        vault.store(credential_ref, secrets.token_bytes(24))

    assert vault.resolve(credential_ref).as_bytes() == PLAINTEXT_MARKER


def test_stored_credential_resolves_to_original_bytes(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)

    resolved = vault.resolve(credential_ref)

    assert isinstance(resolved, BrokerCredential)
    assert resolved.as_bytes() == PLAINTEXT_MARKER


def test_unknown_credential_fails_closed(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)

    with pytest.raises(VaultError, match="credential does not exist"):
        vault.resolve(CredentialRef("credential-unknown"))


def test_tampered_ciphertext_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    row = read_credential_row(database_path, credential_ref.id)
    assert row is not None
    ciphertext = row[2]
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    update_credential_field(
        database_path,
        "ciphertext",
        tampered,
        credential_ref.id,
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        vault.resolve(credential_ref)


def test_tampered_nonce_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    row = read_credential_row(database_path, credential_ref.id)
    assert row is not None
    nonce = row[1]
    tampered = bytes([nonce[0] ^ 1]) + nonce[1:]
    update_credential_field(
        database_path,
        "nonce",
        tampered,
        credential_ref.id,
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        vault.resolve(credential_ref)


def test_malformed_nonce_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    update_credential_field(
        database_path,
        "nonce",
        secrets.token_bytes(11),
        credential_ref.id,
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        vault.resolve(credential_ref)


def test_malformed_ciphertext_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    update_credential_field(
        database_path,
        "ciphertext",
        b"",
        credential_ref.id,
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        vault.resolve(credential_ref)


def test_unsupported_encryption_version_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    update_credential_field(
        database_path,
        "encryption_version",
        999,
        credential_ref.id,
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        vault.resolve(credential_ref)


def test_wrong_master_key_fails_closed(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    wrong_key_vault = SQLiteVault(
        database_path,
        AesGcmSecretCipher(secrets.token_bytes(32)),
    )

    with pytest.raises(
        VaultError,
        match="credential could not be decrypted",
    ):
        wrong_key_vault.resolve(credential_ref)


def test_database_file_contains_neither_plaintext_nor_master_key(
    tmp_path: Path,
):
    vault, database_path, master_key = make_vault(tmp_path)
    vault.store(CredentialRef("credential-001"), PLAINTEXT_MARKER)

    database_bytes = database_path.read_bytes()

    assert PLAINTEXT_MARKER not in database_bytes
    assert master_key not in database_bytes


def test_vault_errors_and_repr_do_not_expose_plaintext(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    update_credential_field(
        database_path,
        "ciphertext",
        secrets.token_bytes(32),
        credential_ref.id,
    )

    with pytest.raises(VaultError) as captured:
        vault.resolve(credential_ref)

    plaintext_text = PLAINTEXT_MARKER.decode()
    assert plaintext_text not in str(captured.value)
    assert plaintext_text not in repr(vault)


def test_parameterized_lookup_does_not_treat_id_as_sql(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)
    vault.store(CredentialRef("credential-001"), PLAINTEXT_MARKER)
    malicious_ref = CredentialRef("' OR 1=1 --")

    with pytest.raises(VaultError, match="credential does not exist"):
        vault.resolve(malicious_ref)


def test_resolve_does_not_mutate_credential_ref(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)

    vault.resolve(credential_ref)

    assert credential_ref == CredentialRef("credential-001")


def test_sqlite_vault_satisfies_vault_port_contract(tmp_path: Path):
    vault, _, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    vault_port: VaultPort = vault

    resolved = vault_port.resolve(credential_ref)

    assert resolved is not None
    assert resolved.as_bytes() == PLAINTEXT_MARKER


def test_broker_credential_repr_is_redacted():
    credential = BrokerCredential(PLAINTEXT_MARKER)

    assert PLAINTEXT_MARKER.decode() not in repr(credential)
    assert {field.name for field in fields(BrokerCredential)} == {"_value"}
