"""One-shot provisioning for the local PAM integration lab.

Passwords are read without echo and live briefly in process memory. Python
cannot guarantee deterministic zeroization. If provisioning fails after files
have been created in a fresh runtime directory, inspect that directory and
remove it manually before provisioning again. Existing files are never wiped.
"""

import argparse
import base64
import binascii
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import getpass
import hmac
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Iterator

from src.domain.access import AccessAction, AccessEffect, AccessPolicy
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import HostKeyFingerprint, Target
from src.domain.user import User
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
from src.infrastructure.security.errors import KeyProviderError
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.infrastructure.vault.sqlite_vault import SQLiteVault


DEFAULT_USER_ID = "user-001"
DEFAULT_USERNAME = "goksu"
DEFAULT_TARGET_ID = "target-001"
DEFAULT_TARGET_NAME = "linux-server-1"
DEFAULT_TARGET_HOST = "192.168.122.227"
DEFAULT_TARGET_PORT = 22
DEFAULT_HOST_KEY_FINGERPRINT = (
    "SHA256:sN8IiNCiH3HWetmR/J3uRvPfer4s0AcIP3BebXieUuI"
)
DEFAULT_CREDENTIAL_REF = "cred-001"
DEFAULT_ACCOUNT_ID = "account-001"
DEFAULT_ACCOUNT_USERNAME = "pamadmin"
DEFAULT_POLICY_ID = "policy-001"


class LabProvisioningError(Exception):
    """Raised when the lab cannot be provisioned safely."""


@dataclass(frozen=True)
class LabProvisioningConfig:
    runtime_dir: Path
    user_id: str = DEFAULT_USER_ID
    username: str = DEFAULT_USERNAME
    target_id: str = DEFAULT_TARGET_ID
    target_name: str = DEFAULT_TARGET_NAME
    target_host: str = DEFAULT_TARGET_HOST
    target_port: int = DEFAULT_TARGET_PORT
    host_key_fingerprint: str = DEFAULT_HOST_KEY_FINGERPRINT
    credential_ref: str = DEFAULT_CREDENTIAL_REF
    account_id: str = DEFAULT_ACCOUNT_ID
    account_username: str = DEFAULT_ACCOUNT_USERNAME
    policy_id: str = DEFAULT_POLICY_ID


@dataclass(frozen=True)
class LabRuntimePaths:
    runtime_dir: Path
    vault_key: Path
    audit_key: Path
    auth_db: Path
    config_db: Path
    vault_db: Path
    audit_db: Path

    @classmethod
    def within(cls, runtime_dir: Path) -> "LabRuntimePaths":
        return cls(
            runtime_dir=runtime_dir,
            vault_key=runtime_dir / "vault.key",
            audit_key=runtime_dir / "audit.key",
            auth_db=runtime_dir / "auth.db",
            config_db=runtime_dir / "config.db",
            vault_db=runtime_dir / "vault.db",
            audit_db=runtime_dir / "audit.db",
        )

    @property
    def databases(self) -> tuple[Path, ...]:
        return self.auth_db, self.config_db, self.vault_db, self.audit_db


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision a fresh local PAM lab runtime",
        epilog=(
            "Passwords are prompted without echo. Existing databases are not "
            "updated; use a fresh runtime directory."
        ),
    )
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--user-id", default=DEFAULT_USER_ID)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--target-id", default=DEFAULT_TARGET_ID)
    parser.add_argument("--target-name", default=DEFAULT_TARGET_NAME)
    parser.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    parser.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    parser.add_argument(
        "--host-key-fingerprint",
        default=DEFAULT_HOST_KEY_FINGERPRINT,
    )
    parser.add_argument("--credential-ref", default=DEFAULT_CREDENTIAL_REF)
    parser.add_argument("--account-id", default=DEFAULT_ACCOUNT_ID)
    parser.add_argument(
        "--account-username",
        default=DEFAULT_ACCOUNT_USERNAME,
    )
    parser.add_argument("--policy-id", default=DEFAULT_POLICY_ID)
    return parser


def provision_lab(
    config: LabProvisioningConfig,
    secret_reader: Callable[[str], str] | None = None,
) -> LabRuntimePaths:
    if not isinstance(config, LabProvisioningConfig):
        raise TypeError("config must be LabProvisioningConfig")

    paths = LabRuntimePaths.within(config.runtime_dir)
    user, target, account, policy = _build_records(config)
    _ensure_private_runtime_directory(paths.runtime_dir)
    _reject_existing_databases(paths)

    vault_key = _load_or_create_key(paths.vault_key, "vault")
    audit_key = _load_or_create_key(paths.audit_key, "audit integrity")
    if hmac.compare_digest(vault_key, audit_key):
        raise LabProvisioningError(
            "vault and audit integrity keys must be distinct"
        )

    try:
        cipher = AesGcmSecretCipher(vault_key)
    except Exception:
        raise LabProvisioningError("vault cipher could not be initialized") from None

    read_secret = getpass.getpass if secret_reader is None else secret_reader
    pam_password = _read_password(
        read_secret,
        "PAM application user password: ",
    )
    try:
        target_password = _read_password(
            read_secret,
            "Target pamadmin SSH password: ",
        )
    except Exception:
        pam_password = ""
        raise

    try:
        with _owner_only_file_creation():
            password_hasher = Argon2PasswordHasher()
            auth_repository = SQLiteUserAuthRepository(
                paths.auth_db,
                password_hasher,
            )
            target_repository = SQLiteTargetRepository(paths.config_db)
            account_repository = SQLitePrivilegedAccountRepository(
                paths.config_db
            )
            policy_repository = SQLitePolicyRepository(paths.config_db)
            vault = SQLiteVault(paths.vault_db, cipher)
    except Exception:
        pam_password = ""
        target_password = ""
        raise LabProvisioningError(
            "lab databases could not be initialized"
        ) from None

    try:
        auth_repository.create_user(user, pam_password)
    except Exception:
        target_password = ""
        raise LabProvisioningError("PAM user could not be provisioned") from None
    finally:
        pam_password = ""

    try:
        target_repository.store(target)
        account_repository.store(account)
        policy_repository.store(policy)
    except Exception:
        target_password = ""
        raise LabProvisioningError(
            "lab configuration could not be provisioned"
        ) from None

    try:
        target_secret = target_password.encode("utf-8")
    except UnicodeError:
        target_password = ""
        raise LabProvisioningError(
            "target password could not be encoded"
        ) from None
    target_password = ""
    try:
        vault.store(account.credential_ref, target_secret)
    except Exception:
        raise LabProvisioningError(
            "target credential could not be encrypted and stored"
        ) from None
    finally:
        target_secret = b""

    return paths


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = build_parser().parse_args(arguments)
    config = LabProvisioningConfig(
        runtime_dir=parsed.runtime_dir,
        user_id=parsed.user_id,
        username=parsed.username,
        target_id=parsed.target_id,
        target_name=parsed.target_name,
        target_host=parsed.target_host,
        target_port=parsed.target_port,
        host_key_fingerprint=parsed.host_key_fingerprint,
        credential_ref=parsed.credential_ref,
        account_id=parsed.account_id,
        account_username=parsed.account_username,
        policy_id=parsed.policy_id,
    )
    try:
        paths = provision_lab(config)
    except LabProvisioningError as error:
        print(f"Provisioning failed: {error}", file=sys.stderr)
        return 1

    print("Provisioning complete.")
    print(f"Runtime directory: {paths.runtime_dir}")
    print(f"PAM user: {config.username}")
    print(
        f"Target: {config.target_name} "
        f"({config.target_host}:{config.target_port})"
    )
    print(f"Privileged account: {config.account_username}")
    print(
        f"Policy: {config.user_id} -> {config.target_id} -> "
        f"{AccessEffect.ALLOW.name}"
    )
    return 0


def _build_records(
    config: LabProvisioningConfig,
) -> tuple[User, Target, PrivilegedAccount, AccessPolicy]:
    try:
        fingerprint = _parse_openssh_sha256_fingerprint(
            config.host_key_fingerprint
        )
        credential_ref = CredentialRef(config.credential_ref)
        user = User(
            id=config.user_id,
            username=config.username,
            is_active=True,
        )
        target = Target(
            id=config.target_id,
            name=config.target_name,
            host=config.target_host,
            port=config.target_port,
            expected_host_key=fingerprint,
            enabled=True,
        )
        account = PrivilegedAccount(
            id=config.account_id,
            target_id=config.target_id,
            username=config.account_username,
            credential_ref=credential_ref,
            enabled=True,
        )
        policy = AccessPolicy(
            id=config.policy_id,
            user_id=config.user_id,
            target_id=config.target_id,
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            effect=AccessEffect.ALLOW,
        )
    except (TypeError, ValueError):
        raise LabProvisioningError(
            "lab configuration contains invalid values"
        ) from None
    return user, target, account, policy


def _parse_openssh_sha256_fingerprint(value: str) -> HostKeyFingerprint:
    try:
        fingerprint = HostKeyFingerprint(value)
        encoded_digest = value.removeprefix("SHA256:")
        if len(encoded_digest) != 43 or "=" in encoded_digest:
            raise ValueError
        digest = base64.b64decode(encoded_digest + "=", validate=True)
        canonical = base64.b64encode(digest).decode("ascii").rstrip("=")
        if len(digest) != 32 or not hmac.compare_digest(
            encoded_digest,
            canonical,
        ):
            raise ValueError
    except (AttributeError, binascii.Error, TypeError, ValueError):
        raise LabProvisioningError(
            "target host-key fingerprint is malformed"
        ) from None
    return fingerprint


def _ensure_private_runtime_directory(runtime_dir: Path) -> None:
    if not isinstance(runtime_dir, Path):
        raise LabProvisioningError("runtime directory path is invalid")
    descriptor: int | None = None
    try:
        if runtime_dir.is_symlink():
            raise LabProvisioningError(
                "runtime directory must not be a symbolic link"
            )
        existed = runtime_dir.exists()
        runtime_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        descriptor = os.open(
            runtime_dir,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        if not existed:
            os.fchmod(descriptor, 0o700)
        file_stat = os.fstat(descriptor)
    except LabProvisioningError:
        raise
    except OSError:
        raise LabProvisioningError(
            "runtime directory could not be created or inspected"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not stat.S_ISDIR(file_stat.st_mode):
        raise LabProvisioningError("runtime path is not a directory")
    if stat.S_IMODE(file_stat.st_mode) != 0o700:
        raise LabProvisioningError(
            "runtime directory permissions must be owner-only (0700)"
        )


def _reject_existing_databases(paths: LabRuntimePaths) -> None:
    if any(path.exists() for path in paths.databases):
        raise LabProvisioningError(
            "a lab database already exists; use a fresh runtime directory"
        )


def _load_or_create_key(path: Path, purpose: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        descriptor = None
    except OSError:
        raise LabProvisioningError(
            f"{purpose} key file could not be created"
        ) from None

    if descriptor is not None:
        key = secrets.token_bytes(FileKeyProvider.KEY_SIZE)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as key_stream:
                descriptor = None
                key_stream.write(key)
                key_stream.flush()
                os.fsync(key_stream.fileno())
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise LabProvisioningError(
                f"{purpose} key file could not be written"
            ) from None

    try:
        return FileKeyProvider(path).get_key()
    except KeyProviderError:
        raise LabProvisioningError(
            f"{purpose} key file is invalid or has unsafe permissions"
        ) from None


def _read_password(
    secret_reader: Callable[[str], str],
    prompt: str,
) -> str:
    try:
        password = secret_reader(prompt)
    except (EOFError, KeyboardInterrupt):
        raise LabProvisioningError("secret entry was cancelled") from None
    if type(password) is not str or not password:
        raise LabProvisioningError("password cannot be empty")
    return password


@contextmanager
def _owner_only_file_creation() -> Iterator[None]:
    previous_umask = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
