from contextlib import closing
from pathlib import Path
import sqlite3

from src.domain.privileged_account import CredentialRef
from src.infrastructure.vault.errors import (
    DuplicateCredentialError,
    VaultError,
)
from src.infrastructure.sqlite_security import (
    DatabasePermissionError,
    ensure_owner_only_database_file,
)
from src.ports.security import EncryptedSecret, SecretCipher
from src.ports.session_broker import BrokerCredential


class SQLiteVault:
    def __init__(self, database_path: Path, cipher: SecretCipher) -> None:
        self._database_path = database_path
        self._cipher = cipher
        self._initialize_schema()

    def store(
        self,
        credential_ref: CredentialRef,
        plaintext: bytes,
    ) -> None:
        try:
            encrypted = self._cipher.encrypt(plaintext)
        except Exception as error:
            raise VaultError("credential could not be encrypted") from error

        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO vault_credentials (
                            id,
                            encryption_version,
                            nonce,
                            ciphertext
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            credential_ref.id,
                            encrypted.version,
                            encrypted.nonce,
                            encrypted.ciphertext,
                        ),
                    )
        except sqlite3.IntegrityError as error:
            raise DuplicateCredentialError(
                "credential id already exists"
            ) from error
        except sqlite3.Error as error:
            raise VaultError("credential could not be stored") from error

    def resolve(self, credential_ref: CredentialRef) -> BrokerCredential:
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                row = connection.execute(
                    """
                    SELECT encryption_version, nonce, ciphertext
                    FROM vault_credentials
                    WHERE id = ?
                    """,
                    (credential_ref.id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise VaultError("credential could not be loaded") from error

        if row is None:
            raise VaultError("credential does not exist")

        try:
            encrypted = EncryptedSecret(
                version=row[0],
                nonce=row[1],
                ciphertext=row[2],
            )
            plaintext = self._cipher.decrypt(encrypted)
        except Exception as error:
            raise VaultError("credential could not be decrypted") from error

        return BrokerCredential(plaintext)

    def _initialize_schema(self) -> None:
        try:
            ensure_owner_only_database_file(self._database_path)
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS vault_credentials (
                            id TEXT PRIMARY KEY,
                            encryption_version INTEGER NOT NULL,
                            nonce BLOB NOT NULL,
                            ciphertext BLOB NOT NULL
                        )
                        """
                    )
        except (DatabasePermissionError, sqlite3.Error) as error:
            raise VaultError("vault could not be initialized") from error
