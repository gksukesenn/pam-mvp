import secrets
import sqlite3
from contextlib import closing
from dataclasses import fields
from pathlib import Path

import pytest

from src.domain.privileged_account import CredentialRef
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.vault.errors import (
    DuplicateCredentialError,
    UnsupportedVaultSchemaError,
    VaultError,
)
from src.infrastructure.vault.sqlite_vault import SCHEMA_VERSION, SQLiteVault
from src.ports.access_dependencies import VaultPort
from src.ports.session_broker import BrokerCredential

PLAINTEXT_MARKER = b"PAM-PHASE-5B-PLAINTEXT-CREDENTIAL-DO-NOT-PERSIST"


class NeverDecryptCipher:
    def __init__(self) -> None:
        self.decrypt_calls = 0

    def decrypt(self, encrypted: object) -> bytes:
        self.decrypt_calls += 1
        raise AssertionError("malformed rows must not reach decryption")


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
        schema_version = connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(vault_credentials)"
            ).fetchall()
        ]
    assert schema_version == SCHEMA_VERSION
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


def test_valid_vault_reopens_without_changing_credential(tmp_path: Path):
    vault, database_path, master_key = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    original_row = read_credential_row(database_path, credential_ref.id)

    reopened = SQLiteVault(
        database_path,
        AesGcmSecretCipher(master_key),
    )

    assert reopened.resolve(credential_ref).as_bytes() == PLAINTEXT_MARKER
    assert (
        read_credential_row(database_path, credential_ref.id) == original_row
    )


def test_exact_legacy_version_zero_schema_is_upgraded_without_row_changes(
    tmp_path: Path,
):
    database_path = tmp_path / "legacy-vault.db"
    master_key = secrets.token_bytes(32)
    cipher = AesGcmSecretCipher(master_key)
    encrypted = cipher.encrypt(PLAINTEXT_MARKER)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE vault_credentials (
                    id TEXT PRIMARY KEY,
                    encryption_version INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO vault_credentials (
                    id, encryption_version, nonce, ciphertext
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    "credential-001",
                    encrypted.version,
                    encrypted.nonce,
                    encrypted.ciphertext,
                ),
            )
    original_row = read_credential_row(database_path, "credential-001")

    vault = SQLiteVault(database_path, cipher)

    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION
    assert read_credential_row(database_path, "credential-001") == original_row
    assert vault.resolve(CredentialRef("credential-001")).as_bytes() == (
        PLAINTEXT_MARKER
    )


@pytest.mark.parametrize(
    "schema",
    [
        """
        CREATE TABLE vault_credentials (
            id TEXT PRIMARY KEY,
            encryption_version INTEGER NOT NULL,
            nonce BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE vault_credentials (
            id TEXT PRIMARY KEY,
            encryption_version INTEGER NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            extra TEXT
        )
        """,
        """
        CREATE TABLE vault_credentials (
            id TEXT NOT NULL,
            encryption_version INTEGER NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE vault_credentials (
            id TEXT PRIMARY KEY,
            encryption_version INTEGER,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
        """,
    ],
    ids=(
        "missing-column",
        "extra-column",
        "missing-primary-key",
        "missing-not-null",
    ),
)
def test_incompatible_existing_schema_is_rejected(
    tmp_path: Path,
    schema: str,
):
    database_path = tmp_path / "vault.db"
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(schema)

    with pytest.raises(
        UnsupportedVaultSchemaError,
        match="vault database schema is unsupported",
    ):
        SQLiteVault(
            database_path,
            AesGcmSecretCipher(secrets.token_bytes(32)),
        )


def test_unsupported_schema_version_is_rejected(tmp_path: Path):
    vault, database_path, _ = make_vault(tmp_path)
    del vault
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("PRAGMA user_version = 999")

    with pytest.raises(
        UnsupportedVaultSchemaError,
        match="vault database schema is unsupported",
    ):
        SQLiteVault(
            database_path,
            AesGcmSecretCipher(secrets.token_bytes(32)),
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("encryption_version", "not-an-integer"),
        ("nonce", "not-a-blob"),
        ("ciphertext", "not-a-blob"),
    ],
)
def test_malformed_stored_row_is_rejected_before_decryption(
    tmp_path: Path,
    field_name: str,
    value: object,
):
    vault, database_path, _ = make_vault(tmp_path)
    credential_ref = CredentialRef("credential-001")
    vault.store(credential_ref, PLAINTEXT_MARKER)
    update_credential_field(
        database_path,
        field_name,
        value,
        credential_ref.id,
    )
    never_decrypt = NeverDecryptCipher()
    vault._cipher = never_decrypt

    with pytest.raises(VaultError, match="credential could not be decrypted"):
        vault.resolve(credential_ref)

    assert never_decrypt.decrypt_calls == 0


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
