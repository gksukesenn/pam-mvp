from datetime import timedelta
from pathlib import Path

import pytest

import src.main as main_module
from src.bootstrap import RuntimeSettings


def test_minimal_entrypoint_builds_graph_and_exits_without_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    result = main_module.main(
        [
            "--auth-db",
            str(paths["auth"]),
            "--config-db",
            str(paths["config"]),
            "--vault-db",
            str(paths["vault"]),
            "--audit-db",
            str(paths["audit"]),
            "--vault-key",
            str(paths["vault_key"]),
            "--audit-key",
            str(paths["audit_key"]),
            "--max-session-seconds",
            "1800",
        ]
    )

    assert result == 0
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
