from datetime import timedelta
from pathlib import Path

import pytest

import src.main as main_module
from src.bootstrap import RuntimeSettings


SECRET_MARKER = "VALIDATE-SECRET-MARKER"


def validation_arguments(tmp_path: Path) -> list[str]:
    return [
        "validate",
        "--auth-db",
        str(tmp_path / "auth.db"),
        "--config-db",
        str(tmp_path / "config.db"),
        "--vault-db",
        str(tmp_path / "vault.db"),
        "--audit-db",
        str(tmp_path / "audit.db"),
        "--vault-key",
        str(tmp_path / "vault.key"),
        "--audit-key",
        str(tmp_path / "audit.key"),
        "--max-session-seconds",
        "1800",
    ]


def test_minimal_entrypoint_builds_graph_and_exits_without_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    received: list[RuntimeSettings] = []

    def record_build(settings: RuntimeSettings) -> object:
        received.append(settings)
        return object()

    monkeypatch.setattr(main_module, "build_application", record_build)
    paths = {
        "auth": tmp_path / "auth.db",
        "config": tmp_path / "config.db",
        "vault": tmp_path / "vault.db",
        "audit": tmp_path / "audit.db",
        "vault_key": tmp_path / "vault.key",
        "audit_key": tmp_path / "audit.key",
    }

    result = main_module.main(validation_arguments(tmp_path))

    assert result == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert received == [
        RuntimeSettings(
            auth_db_path=paths["auth"],
            config_db_path=paths["config"],
            vault_db_path=paths["vault"],
            audit_db_path=paths["audit"],
            vault_key_path=paths["vault_key"],
            audit_integrity_key_path=paths["audit_key"],
            max_session_duration=timedelta(minutes=30),
        )
    ]


def test_validation_missing_key_fails_without_traceback_or_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    result = main_module.main(validation_arguments(tmp_path))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert captured.out == ""
    assert captured.err == "Runtime validation failed.\n"
    assert "Traceback" not in captured.err
    assert SECRET_MARKER not in captured.out + captured.err


def test_validation_unsafe_key_fails_without_secret_or_internal_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    vault_key = tmp_path / "vault.key"
    audit_key = tmp_path / "audit.key"
    vault_key.write_bytes((SECRET_MARKER.encode() + b"x" * 32)[:32])
    audit_key.write_bytes(b"a" * 32)
    vault_key.chmod(0o640)
    audit_key.chmod(0o600)

    result = main_module.main(validation_arguments(tmp_path))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert captured.out == ""
    assert captured.err == "Runtime validation failed.\n"
    assert "Traceback" not in captured.err
    assert SECRET_MARKER not in captured.out + captured.err
