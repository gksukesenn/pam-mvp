from contextlib import closing
from datetime import timedelta
from pathlib import Path
import secrets
import socket
import sqlite3
import stat

import pytest

import src.tools.provision_lab as provision_module
from src.application.authentication_service import AuthenticationFailedError
from src.bootstrap import RuntimeSettings, build_application
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessRequest,
)
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.security.aes_gcm_cipher import AesGcmSecretCipher
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.infrastructure.vault.sqlite_vault import SQLiteVault
from src.tools.provision_lab import (
    DEFAULT_HOST_KEY_FINGERPRINT,
    LabProvisioningConfig,
    LabProvisioningError,
    main,
    provision_lab,
)


PAM_PASSWORD = "PAM-PROVISIONING-LOGIN-SECRET-MARKER"
TARGET_PASSWORD = "PAM-PROVISIONING-TARGET-SECRET-MARKER"


def write_key(path: Path, key: bytes, mode: int = 0o600) -> None:
    path.write_bytes(key)
    path.chmod(mode)


def secret_reader(prompts: list[str]):
    values = iter((PAM_PASSWORD, TARGET_PASSWORD))

    def read(prompt: str) -> str:
        prompts.append(prompt)
        return next(values)

    return read


def provision_successfully(
    tmp_path: Path,
) -> tuple[Path, list[str]]:
    runtime_dir = tmp_path / "runtime" / "lab"
    prompts: list[str] = []
    provision_lab(
        LabProvisioningConfig(runtime_dir=runtime_dir),
        secret_reader(prompts),
    )
    return runtime_dir, prompts


def test_provisions_distinct_private_keys_and_exact_secure_records(
    tmp_path: Path,
):
    runtime_dir, prompts = provision_successfully(tmp_path)
    vault_key_path = runtime_dir / "vault.key"
    audit_key_path = runtime_dir / "audit.key"
    vault_key = vault_key_path.read_bytes()
    audit_key = audit_key_path.read_bytes()

    assert prompts == [
        "PAM application user password: ",
        "Target pamadmin SSH password: ",
    ]
    assert len(vault_key) == len(audit_key) == 32
    assert vault_key != audit_key
    assert stat.S_IMODE(runtime_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(vault_key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(audit_key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((runtime_dir / "auth.db").stat().st_mode) == 0o600
    assert stat.S_IMODE((runtime_dir / "config.db").stat().st_mode) == 0o600
    assert stat.S_IMODE((runtime_dir / "vault.db").stat().st_mode) == 0o600
    assert not (runtime_dir / "audit.db").exists()

    with closing(sqlite3.connect(runtime_dir / "auth.db")) as connection:
        auth_row = connection.execute(
            "SELECT id, username, password_hash, enabled FROM pam_users"
        ).fetchone()
    assert auth_row is not None
    assert auth_row[:2] == ("user-001", "goksu")
    assert auth_row[2].startswith("$argon2id$")
    assert auth_row[3] == 1
    assert PAM_PASSWORD not in auth_row[2]

    with closing(sqlite3.connect(runtime_dir / "config.db")) as connection:
        target_row = connection.execute(
            """
            SELECT id, name, host, port, expected_host_key, enabled
            FROM targets
            """
        ).fetchone()
        account_row = connection.execute(
            """
            SELECT id, target_id, username, credential_ref, enabled
            FROM privileged_accounts
            """
        ).fetchone()
        policy_row = connection.execute(
            """
            SELECT id, user_id, target_id, action, effect
            FROM access_policies
            """
        ).fetchone()
    assert target_row == (
        "target-001",
        "linux-server-1",
        "192.168.122.227",
        22,
        DEFAULT_HOST_KEY_FINGERPRINT,
        1,
    )
    assert account_row == (
        "account-001",
        "target-001",
        "pamadmin",
        "cred-001",
        1,
    )
    assert policy_row == (
        "policy-001",
        "user-001",
        "target-001",
        AccessAction.OPEN_PRIVILEGED_SESSION.value,
        AccessEffect.ALLOW.value,
    )

    with closing(sqlite3.connect(runtime_dir / "vault.db")) as connection:
        vault_row = connection.execute(
            """
            SELECT id, encryption_version, nonce, ciphertext
            FROM vault_credentials
            """
        ).fetchone()
    assert vault_row is not None
    assert vault_row[0] == "cred-001"
    assert vault_row[1] == 1
    assert len(vault_row[2]) == 12
    assert vault_row[3]

    raw_auth = (runtime_dir / "auth.db").read_bytes()
    raw_config = (runtime_dir / "config.db").read_bytes()
    raw_vault = (runtime_dir / "vault.db").read_bytes()
    all_database_bytes = raw_auth + raw_config + raw_vault
    for marker in (PAM_PASSWORD.encode(), TARGET_PASSWORD.encode()):
        assert marker not in raw_auth
        assert marker not in raw_config
        assert marker not in raw_vault
    assert b"$argon2id$" in raw_auth
    assert vault_row[2] not in raw_config
    assert vault_row[3] not in raw_config
    assert vault_key not in all_database_bytes
    assert audit_key not in all_database_bytes

    vault = SQLiteVault(
        runtime_dir / "vault.db",
        AesGcmSecretCipher(FileKeyProvider(vault_key_path).get_key()),
    )
    assert vault.resolve(CredentialRef("cred-001")).as_bytes() == (
        TARGET_PASSWORD.encode()
    )


def test_cli_uses_getpass_and_output_contains_only_non_secret_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = tmp_path / "runtime" / "lab"
    prompts: list[str] = []
    monkeypatch.setattr(
        provision_module.getpass,
        "getpass",
        secret_reader(prompts),
    )

    result = main(["--runtime-dir", str(runtime_dir)])

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert result == 0
    assert prompts == [
        "PAM application user password: ",
        "Target pamadmin SSH password: ",
    ]
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "Provisioning complete.",
        f"Runtime directory: {runtime_dir}",
        "PAM user: goksu",
        "Target: linux-server-1 (192.168.122.227:22)",
        "Privileged account: pamadmin",
        "Policy: user-001 -> target-001 -> ALLOW",
    ]
    forbidden = (
        PAM_PASSWORD,
        TARGET_PASSWORD,
        repr((runtime_dir / "vault.key").read_bytes()),
        (runtime_dir / "vault.key").read_bytes().hex(),
        repr((runtime_dir / "audit.key").read_bytes()),
        (runtime_dir / "audit.key").read_bytes().hex(),
        "$argon2id$",
        "BrokerCredential",
    )
    assert all(value not in combined for value in forbidden)


def test_existing_valid_keys_are_preserved(tmp_path: Path):
    runtime_dir = tmp_path / "lab"
    runtime_dir.mkdir(mode=0o700)
    vault_key = secrets.token_bytes(32)
    audit_key = secrets.token_bytes(32)
    while audit_key == vault_key:
        audit_key = secrets.token_bytes(32)
    write_key(runtime_dir / "vault.key", vault_key)
    write_key(runtime_dir / "audit.key", audit_key)

    provision_lab(
        LabProvisioningConfig(runtime_dir=runtime_dir),
        secret_reader([]),
    )

    assert (runtime_dir / "vault.key").read_bytes() == vault_key
    assert (runtime_dir / "audit.key").read_bytes() == audit_key


def test_identical_keys_fail_without_prompt_or_secret_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = tmp_path / "lab"
    runtime_dir.mkdir(mode=0o700)
    shared_key = secrets.token_bytes(32)
    write_key(runtime_dir / "vault.key", shared_key)
    write_key(runtime_dir / "audit.key", shared_key)

    with pytest.raises(
        LabProvisioningError,
        match="vault and audit integrity keys must be distinct",
    ) as captured_error:
        provision_lab(
            LabProvisioningConfig(runtime_dir=runtime_dir),
            lambda prompt: pytest.fail("must fail before prompting"),
        )

    captured = capsys.readouterr()
    all_output = captured.out + captured.err + str(captured_error.value)
    assert repr(shared_key) not in all_output
    assert shared_key.hex() not in all_output
    assert not any(
        (runtime_dir / name).exists()
        for name in ("auth.db", "config.db", "vault.db")
    )


def test_unsafe_existing_key_permissions_fail_without_replacement(
    tmp_path: Path,
):
    runtime_dir = tmp_path / "lab"
    runtime_dir.mkdir(mode=0o700)
    unsafe_key = secrets.token_bytes(32)
    write_key(runtime_dir / "vault.key", unsafe_key, 0o640)

    with pytest.raises(
        LabProvisioningError,
        match="vault key file is invalid or has unsafe permissions",
    ):
        provision_lab(
            LabProvisioningConfig(runtime_dir=runtime_dir),
            lambda prompt: pytest.fail("must fail before prompting"),
        )

    assert (runtime_dir / "vault.key").read_bytes() == unsafe_key
    assert stat.S_IMODE((runtime_dir / "vault.key").stat().st_mode) == 0o640


def test_rerun_aborts_before_prompt_and_does_not_overwrite(tmp_path: Path):
    runtime_dir, _ = provision_successfully(tmp_path)
    paths = tuple(runtime_dir.iterdir())
    original = {path.name: path.read_bytes() for path in paths}

    with pytest.raises(
        LabProvisioningError,
        match="a lab database already exists; use a fresh runtime directory",
    ):
        provision_lab(
            LabProvisioningConfig(runtime_dir=runtime_dir),
            lambda prompt: pytest.fail("rerun must not prompt"),
        )

    assert {path.name: path.read_bytes() for path in paths} == original


def test_malformed_fingerprint_fails_before_prompt_or_file_creation(
    tmp_path: Path,
):
    runtime_dir = tmp_path / "lab"

    with pytest.raises(
        LabProvisioningError,
        match="target host-key fingerprint is malformed",
    ):
        provision_lab(
            LabProvisioningConfig(
                runtime_dir=runtime_dir,
                host_key_fingerprint="SHA256:not-a-complete-digest",
            ),
            lambda prompt: pytest.fail("must fail before prompting"),
        )

    assert not runtime_dir.exists()


def test_provisioned_runtime_builds_real_graph_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    runtime_dir, _ = provision_successfully(tmp_path)

    def reject_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("composition must not connect to SSH")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    settings = RuntimeSettings(
        auth_db_path=runtime_dir / "auth.db",
        config_db_path=runtime_dir / "config.db",
        vault_db_path=runtime_dir / "vault.db",
        audit_db_path=runtime_dir / "audit.db",
        vault_key_path=runtime_dir / "vault.key",
        audit_integrity_key_path=runtime_dir / "audit.key",
        max_session_duration=timedelta(minutes=30),
    )

    services = build_application(settings)
    principal = services.authentication.authenticate("goksu", PAM_PASSWORD)

    assert principal.user_id == "user-001"
    assert principal.username == "goksu"
    with pytest.raises(AuthenticationFailedError):
        services.authentication.authenticate("goksu", "wrong-password")

    target = services.access._target_repository.get("target-001")
    assert target == Target(
        id="target-001",
        name="linux-server-1",
        host="192.168.122.227",
        port=22,
        expected_host_key=HostKeyFingerprint(DEFAULT_HOST_KEY_FINGERPRINT),
        enabled=True,
    )
    assert services.access._account_repository.find_for_target(
        "target-001"
    ) == PrivilegedAccount(
        id="account-001",
        target_id="target-001",
        username="pamadmin",
        credential_ref=CredentialRef("cred-001"),
        enabled=True,
    )
    decision = services.access._policy_evaluator.evaluate(
        AccessRequest(
            id="request-composition-check",
            user_id="user-001",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            requested_at=services.access._clock.now(),
        )
    )
    assert decision.effect is AccessEffect.ALLOW
    assert decision.reason == "policy-001"


def test_cli_exposes_no_password_argument_and_runtime_is_gitignored():
    option_strings = {
        option
        for action in provision_module.build_parser()._actions
        for option in action.option_strings
    }
    repository_root = Path(__file__).resolve().parents[2]

    assert not any("password" in option for option in option_strings)
    assert "runtime/" in (repository_root / ".gitignore").read_text().splitlines()
