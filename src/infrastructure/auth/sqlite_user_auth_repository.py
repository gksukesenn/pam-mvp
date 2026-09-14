import sqlite3
from contextlib import closing
from pathlib import Path

from src.domain.user import User
from src.infrastructure.auth.errors import (
    DuplicateUserIdError,
    DuplicateUsernameError,
    MalformedUserAuthError,
    UnsupportedUserAuthSchemaError,
    UserAuthStorageError,
)
from src.infrastructure.sqlite_security import (
    DatabasePermissionError,
    ensure_owner_only_database_file,
)
from src.ports.authentication import PasswordHasher, StoredUserAuthentication

SCHEMA_VERSION = 1
SCHEMA_DEFINITION = (
    ("id", "TEXT", 0, None, 1),
    ("username", "TEXT", 1, None, 0),
    ("password_hash", "TEXT", 1, None, 0),
    ("enabled", "INTEGER", 1, None, 0),
)


class SQLiteUserAuthRepository:
    """Separate SQLite storage and provisioning for local PAM users."""

    __slots__ = ("_database_path", "_password_hasher")

    def __init__(
        self,
        database_path: Path,
        password_hasher: PasswordHasher,
    ) -> None:
        self._database_path = database_path
        self._password_hasher = password_hasher
        self._initialize_schema()

    def create_user(self, user: User, password: str) -> None:
        serialized_user = self._serialize_user(user)
        try:
            encoded_hash = self._password_hasher.hash_password(password)
        except Exception:
            raise UserAuthStorageError(
                "PAM user could not be created"
            ) from None
        if (
            type(encoded_hash) is not str
            or not encoded_hash.startswith("$argon2id$")
        ):
            raise UserAuthStorageError("PAM user could not be created")

        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO pam_users (
                            id,
                            username,
                            password_hash,
                            enabled
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (*serialized_user, encoded_hash, int(user.is_active)),
                    )
        except sqlite3.IntegrityError as error:
            message = str(error)
            if "pam_users.username" in message:
                raise DuplicateUsernameError(
                    "PAM username already exists"
                ) from error
            if "pam_users.id" in message:
                raise DuplicateUserIdError(
                    "PAM user id already exists"
                ) from error
            raise UserAuthStorageError(
                "PAM user could not be created"
            ) from error
        except sqlite3.Error as error:
            raise UserAuthStorageError(
                "PAM user could not be created"
            ) from error

    def find_by_username(
        self,
        username: str,
    ) -> StoredUserAuthentication | None:
        if type(username) is not str:
            raise UserAuthStorageError("PAM user could not be loaded")
        try:
            with closing(sqlite3.connect(self._database_path)) as connection:
                row = connection.execute(
                    """
                    SELECT id, username, password_hash, enabled
                    FROM pam_users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()
        except sqlite3.Error as error:
            raise UserAuthStorageError(
                "PAM user could not be loaded"
            ) from error

        if row is None:
            return None
        return self._deserialize(row)

    @staticmethod
    def _serialize_user(user: User) -> tuple[str, str]:
        if (
            not isinstance(user, User)
            or type(user.id) is not str
            or not user.id.strip()
            or type(user.username) is not str
            or not user.username.strip()
            or type(user.is_active) is not bool
        ):
            raise UserAuthStorageError(
                "PAM user contains unsupported field values"
            )
        return user.id, user.username

    @staticmethod
    def _deserialize(row: object) -> StoredUserAuthentication:
        if (
            not isinstance(row, tuple)
            or len(row) != len(SCHEMA_DEFINITION)
            or not all(type(value) is str for value in row[:3])
            or not all(value.strip() for value in row[:3])
            or not row[2].startswith("$argon2id$")
            or type(row[3]) is not int
            or row[3] not in (0, 1)
        ):
            raise MalformedUserAuthError(
                "PAM user contains invalid stored values"
            )
        user_id, username, password_hash, enabled = row
        try:
            user = User(
                id=user_id,
                username=username,
                is_active=bool(enabled),
            )
        except (TypeError, ValueError) as error:
            raise MalformedUserAuthError(
                "PAM user contains invalid stored values"
            ) from error
        return StoredUserAuthentication(
            user=user,
            password_hash=password_hash,
        )

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
                        ("table", "pam_users"),
                    ).fetchone() is not None
                    if table_exists:
                        self._validate_existing_schema(connection, version)
                    elif version == 0:
                        self._create_schema(connection)
                    else:
                        raise UnsupportedUserAuthSchemaError(
                            "authentication database schema is unsupported"
                        )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except UserAuthStorageError:
            raise
        except (DatabasePermissionError, sqlite3.Error) as error:
            raise UserAuthStorageError(
                "authentication database could not be initialized"
            ) from error

    @staticmethod
    def _validate_existing_schema(
        connection: sqlite3.Connection,
        version: int,
    ) -> None:
        definition = tuple(
            (row[1], row[2].upper(), row[3], row[4], row[5])
            for row in connection.execute(
                "PRAGMA table_info(pam_users)"
            ).fetchall()
        )
        unique_columns = {
            tuple(
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM pragma_index_info(?)
                    ORDER BY seqno
                    """,
                    (index[1],),
                ).fetchall()
            )
            for index in connection.execute(
                "PRAGMA index_list(pam_users)"
            ).fetchall()
            if index[2] == 1
        }
        if (
            version != SCHEMA_VERSION
            or definition != SCHEMA_DEFINITION
            or ("id",) not in unique_columns
            or ("username",) not in unique_columns
        ):
            raise UnsupportedUserAuthSchemaError(
                "authentication database schema is unsupported"
            )

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE pam_users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL
            )
            """
        )
        connection.execute("PRAGMA user_version = 1")
