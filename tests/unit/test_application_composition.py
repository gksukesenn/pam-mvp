from dataclasses import FrozenInstanceError, fields
from datetime import timedelta
from pathlib import Path
import secrets
import socket
import stat

import pytest

import src.bootstrap.application as application_module
from src.application.access_service import AccessService
from src.application.authentication_service import AuthenticationService
from src.bootstrap.application import (
    ApplicationConfigurationError,
    ApplicationServices,
    RuntimeSettings,
    build_application,
)
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
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
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.security.errors import KeyProviderError
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.infrastructure.ssh.paramiko_connection import ParamikoSshConnector
from src.infrastructure.ssh.paramiko_session_broker import ParamikoSessionBroker
from src.infrastructure.terminal.local_terminal_io import LocalTerminalIO
from src.infrastructure.vault.errors import VaultError
from src.infrastructure.vault.sqlite_vault import SQLiteVault


PLAINTEXT_MARKER = b"COMPOSITION-MUST-NOT-NEED-A-PLAINTEXT-CREDENTIAL"


def write_key(path: Path, key: bytes, mode: int = 0o600) -> None:
    path.write_bytes(key)
    path.chmod(mode)


def make_settings(tmp_path: Path) -> RuntimeSettings:
    vault_key_path = tmp_path / "vault.key"
    audit_key_path = tmp_path / "audit.key"
    write_key(vault_key_path, secrets.token_bytes(32))
    write_key(audit_key_path, secrets.token_bytes(32))
    return RuntimeSettings(
        auth_db_path=tmp_path / "auth.db",
        config_db_path=tmp_path / "config.db",
        vault_db_path=tmp_path / "vault.db",
        audit_db_path=tmp_path / "audit.db",
        vault_key_path=vault_key_path,
        audit_integrity_key_path=audit_key_path,
        max_session_duration=timedelta(minutes=30),
    )


def test_runtime_settings_are_immutable_and_contain_only_paths_and_duration(
    tmp_path: Path,
):
    settings = make_settings(tmp_path)

    assert {field.name for field in fields(settings)} == {
        "auth_db_path",
        "config_db_path",
        "vault_db_path",
        "audit_db_path",
        "vault_key_path",
        "audit_integrity_key_path",
        "max_session_duration",
    }
    assert PLAINTEXT_MARKER.decode() not in repr(settings)
    with pytest.raises(FrozenInstanceError):
        settings.auth_db_path = tmp_path / "replacement.db"


@pytest.mark.parametrize(
    "duration",
    [timedelta(0), timedelta(microseconds=-1)],
)
def test_runtime_settings_reject_nonpositive_session_duration(
    tmp_path: Path,
    duration: timedelta,
):
    valid = make_settings(tmp_path)

    with pytest.raises(
        ValueError,
        match="max_session_duration must be positive",
    ):
        RuntimeSettings(
            auth_db_path=valid.auth_db_path,
            config_db_path=valid.config_db_path,
            vault_db_path=valid.vault_db_path,
            audit_db_path=valid.audit_db_path,
            vault_key_path=valid.vault_key_path,
            audit_integrity_key_path=valid.audit_integrity_key_path,
            max_session_duration=duration,
        )


def test_build_application_wires_real_graph_without_network_or_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    settings = make_settings(tmp_path)

    def reject_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("construction must not connect to SSH")

    monkeypatch.setattr(socket, "create_connection", reject_network)

    services = build_application(settings)

    assert isinstance(services, ApplicationServices)
    assert services.settings is settings
    assert isinstance(services.authentication, AuthenticationService)
    assert isinstance(services.access, AccessService)
    assert isinstance(services.terminal_io, LocalTerminalIO)

    auth_repository = services.authentication._repository
    assert isinstance(auth_repository, SQLiteUserAuthRepository)
    assert auth_repository._database_path == settings.auth_db_path

    policy_evaluator = services.access._policy_evaluator
    assert isinstance(policy_evaluator._policy_repository, SQLitePolicyRepository)
    assert policy_evaluator._policy_repository._database_path == (
        settings.config_db_path
    )
    assert isinstance(services.access._target_repository, SQLiteTargetRepository)
    assert services.access._target_repository._database_path == (
        settings.config_db_path
    )
    assert isinstance(
        services.access._account_repository,
        SQLitePrivilegedAccountRepository,
    )
    assert services.access._account_repository._database_path == (
        settings.config_db_path
    )
    assert isinstance(services.access._vault, SQLiteVault)
    assert services.access._vault._database_path == settings.vault_db_path
    assert isinstance(services.access._vault._cipher, AesGcmSecretCipher)
    assert isinstance(
        services.access._audit_repository,
        SQLiteAuditRepository,
    )
    assert services.access._audit_repository._database_path == (
        settings.audit_db_path
    )
    assert isinstance(services.access._session_broker, ParamikoSessionBroker)
    assert isinstance(
        services.access._session_broker._connector,
        ParamikoSshConnector,
    )

    database_paths = (
        settings.auth_db_path,
        settings.config_db_path,
        settings.vault_db_path,
        settings.audit_db_path,
    )
    assert all(path.exists() for path in database_paths)
    assert len({path.resolve() for path in database_paths}) == 4
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in database_paths
    )
    assert all(PLAINTEXT_MARKER not in path.read_bytes() for path in database_paths)


def test_build_uses_distinct_key_provider_instances_and_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    settings = make_settings(tmp_path)
    providers: list[FileKeyProvider] = []

    class RecordingFileKeyProvider(FileKeyProvider):
        def __init__(self, key_file: Path) -> None:
            super().__init__(key_file)
            providers.append(self)

    monkeypatch.setattr(
        application_module,
        "FileKeyProvider",
        RecordingFileKeyProvider,
    )

    services = build_application(settings)

    assert len(providers) == 2
    assert providers[0] is not providers[1]
    assert providers[0]._key_file == settings.vault_key_path
    assert providers[1]._key_file == settings.audit_integrity_key_path
    assert services.access._audit_repository._key_provider is providers[1]


def test_same_or_canonically_aliased_key_path_is_rejected(tmp_path: Path):
    settings = make_settings(tmp_path)
    aliased_audit_path = tmp_path / "subdirectory" / ".." / "vault.key"
    for audit_key_path in (settings.vault_key_path, aliased_audit_path):
        unsafe = RuntimeSettings(
            auth_db_path=settings.auth_db_path,
            config_db_path=settings.config_db_path,
            vault_db_path=settings.vault_db_path,
            audit_db_path=settings.audit_db_path,
            vault_key_path=settings.vault_key_path,
            audit_integrity_key_path=audit_key_path,
            max_session_duration=settings.max_session_duration,
        )

        with pytest.raises(
            ApplicationConfigurationError,
            match="vault and audit integrity key paths must be distinct",
        ):
            build_application(unsafe)


def test_different_paths_with_same_key_material_are_rejected(tmp_path: Path):
    settings = make_settings(tmp_path)
    shared_key = secrets.token_bytes(32)
    write_key(settings.vault_key_path, shared_key)
    write_key(settings.audit_integrity_key_path, shared_key)

    with pytest.raises(
        ApplicationConfigurationError,
        match="vault and audit integrity keys must be distinct",
    ) as captured:
        build_application(settings)

    assert shared_key.hex() not in repr(captured.value)
    assert repr(shared_key) not in repr(captured.value)


@pytest.mark.parametrize(
    "key_path_field",
    ["vault_key_path", "audit_integrity_key_path"],
)
def test_missing_key_files_fail_during_startup(
    tmp_path: Path,
    key_path_field: str,
):
    settings = make_settings(tmp_path)
    getattr(settings, key_path_field).unlink()

    with pytest.raises(
        KeyProviderError,
        match="master key file does not exist",
    ):
        build_application(settings)


@pytest.mark.parametrize(
    "key_path_field",
    ["vault_key_path", "audit_integrity_key_path"],
)
def test_unsafe_key_file_permissions_fail_during_startup(
    tmp_path: Path,
    key_path_field: str,
):
    settings = make_settings(tmp_path)
    getattr(settings, key_path_field).chmod(0o640)

    with pytest.raises(
        KeyProviderError,
        match="master key file permissions are too broad",
    ):
        build_application(settings)


def test_database_path_aliases_are_rejected_before_initialization(
    tmp_path: Path,
):
    settings = make_settings(tmp_path)
    unsafe = RuntimeSettings(
        auth_db_path=settings.config_db_path,
        config_db_path=settings.config_db_path,
        vault_db_path=settings.vault_db_path,
        audit_db_path=settings.audit_db_path,
        vault_key_path=settings.vault_key_path,
        audit_integrity_key_path=settings.audit_integrity_key_path,
        max_session_duration=settings.max_session_duration,
    )

    with pytest.raises(
        ApplicationConfigurationError,
        match="database paths must be distinct",
    ):
        build_application(unsafe)

    assert not settings.config_db_path.exists()


def test_inaccessible_database_parent_fails_during_startup(tmp_path: Path):
    settings = make_settings(tmp_path)
    inaccessible_path = tmp_path / "missing-parent" / "vault.db"
    unsafe = RuntimeSettings(
        auth_db_path=settings.auth_db_path,
        config_db_path=settings.config_db_path,
        vault_db_path=inaccessible_path,
        audit_db_path=settings.audit_db_path,
        vault_key_path=settings.vault_key_path,
        audit_integrity_key_path=settings.audit_integrity_key_path,
        max_session_duration=settings.max_session_duration,
    )

    with pytest.raises(VaultError, match="vault could not be initialized"):
        build_application(unsafe)

    assert not inaccessible_path.exists()
