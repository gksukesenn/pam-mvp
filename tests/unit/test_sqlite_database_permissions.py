import os
from pathlib import Path
import secrets
import stat

import pytest

from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.auth.argon2_password_hasher import Argon2PasswordHasher
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
from src.infrastructure.vault.sqlite_vault import SQLiteVault


class StaticKeyProvider:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def get_key(self) -> bytes:
        return self._key


def construct_repository(kind: str, database_path: Path) -> object:
    if kind == "audit":
        return SQLiteAuditRepository(
            database_path,
            StaticKeyProvider(secrets.token_bytes(32)),
        )
    if kind == "auth":
        return SQLiteUserAuthRepository(
            database_path,
            Argon2PasswordHasher(),
        )
    if kind == "target":
        return SQLiteTargetRepository(database_path)
    if kind == "account":
        return SQLitePrivilegedAccountRepository(database_path)
    if kind == "policy":
        return SQLitePolicyRepository(database_path)
    if kind == "vault":
        return SQLiteVault(
            database_path,
            AesGcmSecretCipher(secrets.token_bytes(32)),
        )
    raise AssertionError("unsupported test repository")


def test_fresh_audit_database_is_0600_even_with_permissive_umask(
    tmp_path: Path,
):
    database_path = tmp_path / "audit.db"
    previous_umask = os.umask(0)
    try:
        construct_repository("audit", database_path)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(database_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "kind",
    ["auth", "target", "account", "policy", "vault"],
)
def test_other_fresh_pam_databases_are_also_created_0600(
    tmp_path: Path,
    kind: str,
):
    database_path = tmp_path / f"{kind}.db"
    previous_umask = os.umask(0)
    try:
        construct_repository(kind, database_path)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(database_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "kind",
    ["audit", "auth", "target", "account", "policy", "vault"],
)
def test_existing_broad_database_permissions_are_tightened(
    tmp_path: Path,
    kind: str,
):
    database_path = tmp_path / f"{kind}.db"
    database_path.touch()
    database_path.chmod(0o644)

    construct_repository(kind, database_path)

    assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
