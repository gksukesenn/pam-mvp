import sqlite3
from contextlib import closing
from pathlib import Path

from src.domain.privileged_account import CredentialRef
from src.infrastructure.sqlite_security import (
    DatabasePermissionError,
    ensure_owner_only_database_file,
)
from src.infrastructure.vault.errors import (
    DuplicateCredentialError,
    UnsupportedVaultSchemaError,
    VaultError,
)
from src.ports.security import EncryptedSecret, SecretCipher
from src.ports.session_broker import BrokerCredential

SCHEMA_VERSION = 1
SCHEMA_DEFINITION = (
    ("id", "TEXT", 0, None, 1),
    ("encryption_version", "INTEGER", 1, None, 0),
    ("nonce", "BLOB", 1, None, 0),
    ("ciphertext", "BLOB", 1, None, 0),
)


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

        encrypted = self._deserialize(row)
        try:
            plaintext = self._cipher.decrypt(encrypted)
        except Exception as error:
            raise VaultError("credential could not be decrypted") from error

        return BrokerCredential(plaintext)

    @staticmethod
    def _deserialize(row: object) -> EncryptedSecret:
        if (
            not isinstance(row, tuple)
            or len(row) != 3
            or type(row[0]) is not int
            or not isinstance(row[1], bytes)
            or len(row[1]) != 12
            or not isinstance(row[2], bytes)
            or not row[2]
        ):
            raise VaultError("credential could not be decrypted")
        try:
            return EncryptedSecret(
                version=row[0],
                nonce=row[1],
                ciphertext=row[2],
            )
        except (TypeError, ValueError):
            raise VaultError("credential could not be decrypted") from None

    def _initialize_schema(self) -> None:
        try:
            ensure_owner_only_database_file(self._database_path)
            with closing(sqlite3.connect(self._database_path)) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    version = connection.execute(
                        "PRAGMA user_version"
                    ).fetchone()[0]
                    table_exists = connection.execute(
                        """
                        SELECT 1
                        FROM sqlite_master
                        WHERE type = ? AND name = ?
                        """,
                        ("table", "vault_credentials"),
                    ).fetchone() is not None
                    if table_exists:
                        self._validate_existing_schema(connection, version)
                    elif version == 0:
                        self._create_schema(connection)
                    else:
                        raise UnsupportedVaultSchemaError(
                            "vault database schema is unsupported"
                        )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except VaultError:
            raise
        except (DatabasePermissionError, sqlite3.Error) as error:
            raise VaultError("vault could not be initialized") from error

    @staticmethod
    def _validate_existing_schema(
        connection: sqlite3.Connection,
        version: int,
    ) -> None:
        definition = tuple(
            (row[1], row[2].upper(), row[3], row[4], row[5])
            for row in connection.execute(
                "PRAGMA table_info(vault_credentials)"
            ).fetchall()
        )
        if (
            version not in (0, SCHEMA_VERSION)
            or definition != SCHEMA_DEFINITION
        ):
            raise UnsupportedVaultSchemaError(
                "vault database schema is unsupported"
            )
        if version == 0:
            connection.execute("PRAGMA user_version = 1")

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
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
        connection.execute("PRAGMA user_version = 1")
