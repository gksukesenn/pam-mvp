from dataclasses import dataclass
from datetime import timedelta
from hmac import compare_digest
from pathlib import Path

from src.application.access_service import AccessService
from src.application.authentication_service import AuthenticationService
from src.application.policy_evaluator import PolicyEvaluator
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.auth.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from src.infrastructure.auth.sqlite_user_auth_repository import (
    SQLiteUserAuthRepository,
)
from src.infrastructure.config.sqlite_privileged_account_repository import (
    SQLitePrivilegedAccountRepository,
)
from src.infrastructure.config.sqlite_target_repository import (
    SQLiteTargetRepository,
)
from src.infrastructure.policy.sqlite_policy_repository import (
    SQLitePolicyRepository,
)
from src.infrastructure.runtime import SystemClock, UuidIdGenerator
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.infrastructure.ssh.paramiko_connection import ParamikoSshConnector
from src.infrastructure.ssh.paramiko_session_broker import (
    ParamikoSessionBroker,
)
from src.infrastructure.terminal.local_terminal_io import LocalTerminalIO
from src.infrastructure.vault.sqlite_vault import SQLiteVault


class ApplicationConfigurationError(Exception):
    """Raised when runtime paths would create an unsafe application graph."""


@dataclass(frozen=True)
class RuntimeSettings:
    auth_db_path: Path
    config_db_path: Path
    vault_db_path: Path
    audit_db_path: Path
    vault_key_path: Path
    audit_integrity_key_path: Path
    max_session_duration: timedelta

    def __post_init__(self) -> None:
        path_fields = (
            self.auth_db_path,
            self.config_db_path,
            self.vault_db_path,
            self.audit_db_path,
            self.vault_key_path,
            self.audit_integrity_key_path,
        )
        if not all(isinstance(path, Path) for path in path_fields):
            raise TypeError("runtime paths must be pathlib.Path values")
        if not isinstance(self.max_session_duration, timedelta):
            raise TypeError("max_session_duration must be a timedelta")
        if self.max_session_duration <= timedelta(0):
            raise ValueError("max_session_duration must be positive")


@dataclass(frozen=True)
class ApplicationServices:
    settings: RuntimeSettings
    authentication: AuthenticationService
    access: AccessService
    terminal_io: LocalTerminalIO


def build_application(settings: RuntimeSettings) -> ApplicationServices:
    """Validate runtime configuration and wire the production adapters."""

    if not isinstance(settings, RuntimeSettings):
        raise TypeError("settings must be RuntimeSettings")

    _validate_distinct_paths(
        (settings.vault_key_path, settings.audit_integrity_key_path),
        "vault and audit integrity key paths must be distinct",
    )
    _validate_distinct_paths(
        (
            settings.auth_db_path,
            settings.config_db_path,
            settings.vault_db_path,
            settings.audit_db_path,
        ),
        "authentication, config, vault, and audit database paths "
        "must be distinct",
    )

    vault_key_provider = FileKeyProvider(settings.vault_key_path)
    audit_key_provider = FileKeyProvider(settings.audit_integrity_key_path)
    vault_key = vault_key_provider.get_key()
    audit_key = audit_key_provider.get_key()
    if compare_digest(vault_key, audit_key):
        raise ApplicationConfigurationError(
            "vault and audit integrity keys must be distinct"
        )

    vault = SQLiteVault(
        settings.vault_db_path,
        AesGcmSecretCipher(vault_key),
    )
    audit_repository = SQLiteAuditRepository(
        settings.audit_db_path,
        audit_key_provider,
    )
    policy_repository = SQLitePolicyRepository(settings.config_db_path)
    target_repository = SQLiteTargetRepository(settings.config_db_path)
    account_repository = SQLitePrivilegedAccountRepository(
        settings.config_db_path
    )

    password_hasher = Argon2PasswordHasher()
    user_auth_repository = SQLiteUserAuthRepository(
        settings.auth_db_path,
        password_hasher,
    )
    authentication = AuthenticationService(
        user_auth_repository,
        password_hasher,
    )

    session_broker = ParamikoSessionBroker(ParamikoSshConnector())
    access = AccessService(
        policy_evaluator=PolicyEvaluator(policy_repository),
        target_repository=target_repository,
        account_repository=account_repository,
        vault=vault,
        session_broker=session_broker,
        audit_repository=audit_repository,
        clock=SystemClock(),
        id_generator=UuidIdGenerator(),
        max_session_duration=settings.max_session_duration,
    )
    return ApplicationServices(
        settings=settings,
        authentication=authentication,
        access=access,
        terminal_io=LocalTerminalIO(),
    )


def _validate_distinct_paths(
    paths: tuple[Path, ...],
    message: str,
) -> None:
    canonical_paths = tuple(path.resolve(strict=False) for path in paths)
    if len(set(canonical_paths)) != len(canonical_paths):
        raise ApplicationConfigurationError(message)
