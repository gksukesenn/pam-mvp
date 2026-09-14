import base64
import secrets
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.domain.audit import AuditEvent, AuditEventType
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.tools.prepare_negative_lab import (
    BAD_HOST_KEY_FINGERPRINT,
    NegativeLabConfig,
    NegativeLabPreparationError,
    prepare_negative_lab,
)
from src.tools.prepare_negative_lab import (
    main as prepare_main,
)
from src.tools.provision_lab import LabProvisioningConfig, provision_lab
from src.tools.verify_audit import main as verify_main

PAM_PASSWORD = "NEGATIVE-LAB-PAM-PASSWORD-MARKER"  # pragma: allowlist secret
TARGET_PASSWORD = "NEGATIVE-LAB-TARGET-PASSWORD-MARKER"  # pragma: allowlist secret
AUDIT_EVENT_MARKER = "NEGATIVE-LAB-AUDIT-EVENT-MARKER"


def make_baseline(tmp_path: Path) -> Path:
    baseline = tmp_path / "runtime" / "lab"
    passwords = iter((PAM_PASSWORD, TARGET_PASSWORD))
    provision_lab(
        LabProvisioningConfig(runtime_dir=baseline),
        lambda prompt: next(passwords),
    )
    audit_repository = SQLiteAuditRepository(
        baseline / "audit.db",
        FileKeyProvider(baseline / "audit.key"),
    )
    audit_repository.append(
        AuditEvent(
            id="negative-lab-event-001",
            timestamp=datetime(2026, 9, 13, 12, 0, tzinfo=UTC),
            event_type=AuditEventType.SESSION_CLOSED,
            actor_user_id="user-001",
            target_id="target-001",
            session_id="session-001",
            result="closed",
            reason_code=AUDIT_EVENT_MARKER,
        )
    )
    return baseline


def read_config(database_path: Path) -> dict[str, tuple[object, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return {
            "policy": connection.execute(
                """
                SELECT id, user_id, target_id, action, effect
                FROM access_policies WHERE id = 'policy-001'
                """
            ).fetchone(),
            "target": connection.execute(
                """
                SELECT id, name, host, port, expected_host_key, enabled
                FROM targets WHERE id = 'target-001'
                """
            ).fetchone(),
            "account": connection.execute(
                """
                SELECT id, target_id, username, credential_ref, enabled
                FROM privileged_accounts WHERE id = 'account-001'
                """
            ).fetchone(),
        }


def snapshot_files(directory: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }


def test_config_scenarios_change_only_the_intended_copied_field(
    tmp_path: Path,
):
    baseline = make_baseline(tmp_path)
    baseline_snapshot = snapshot_files(baseline)
    baseline_config = read_config(baseline / "config.db")

    for scenario in (
        "deny",
        "disabled-target",
        "disabled-account",
        "bad-host-key",
    ):
        destination = baseline.parent / "scenarios" / scenario
        prepare_negative_lab(
            NegativeLabConfig(
                source=baseline,
                destination=destination,
                scenario=scenario,
            )
        )
        copied_config = read_config(destination / "config.db")
        expected_config = baseline_config.copy()
        if scenario == "deny":
            expected_config["policy"] = (*baseline_config["policy"][:-1], "deny")
        elif scenario == "disabled-target":
            expected_config["target"] = (*baseline_config["target"][:-1], 0)
        elif scenario == "disabled-account":
            expected_config["account"] = (*baseline_config["account"][:-1], 0)
        else:
            target = baseline_config["target"]
            expected_config["target"] = (
                *target[:4],
                BAD_HOST_KEY_FINGERPRINT,
                target[5],
            )
            encoded_digest = BAD_HOST_KEY_FINGERPRINT.removeprefix("SHA256:")
            assert len(base64.b64decode(encoded_digest + "=")) == 32
            assert BAD_HOST_KEY_FINGERPRINT != target[4]

        assert copied_config == expected_config
        assert stat.S_IMODE(destination.stat().st_mode) == 0o700
        destination_snapshot = snapshot_files(destination)
        assert destination_snapshot.keys() == baseline_snapshot.keys()
        for filename, source_bytes in baseline_snapshot.items():
            assert stat.S_IMODE(
                (destination / filename).stat().st_mode
            ) == 0o600
            if filename != "config.db":
                assert destination_snapshot[filename] == source_bytes

    assert snapshot_files(baseline) == baseline_snapshot


def test_prepare_cli_output_is_secret_free_and_runtime_is_gitignored(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    baseline = make_baseline(tmp_path)
    destination = baseline.parent / "scenarios" / "deny"
    key_bytes = (baseline / "vault.key").read_bytes()

    result = prepare_main(
        [
            "--source",
            str(baseline),
            "--destination",
            str(destination),
            "--scenario",
            "deny",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "Negative lab scenario prepared.",
        "Scenario: deny",
        f"Destination: {destination}",
    ]
    forbidden = (
        PAM_PASSWORD,
        TARGET_PASSWORD,
        AUDIT_EVENT_MARKER,
        repr(key_bytes),
        key_bytes.hex(),
        "ciphertext",
        "event_mac",
    )
    assert all(value not in captured.out + captured.err for value in forbidden)
    repository_root = Path(__file__).resolve().parents[2]
    assert "runtime/" in (repository_root / ".gitignore").read_text().splitlines()


def test_preparation_refuses_baseline_and_existing_destinations(
    tmp_path: Path,
):
    baseline = make_baseline(tmp_path)
    baseline_snapshot = snapshot_files(baseline)

    with pytest.raises(
        NegativeLabPreparationError,
        match="destination must not be the baseline runtime",
    ):
        prepare_negative_lab(
            NegativeLabConfig(
                source=baseline,
                destination=baseline,
                scenario="deny",
            )
        )

    destination = baseline.parent / "scenarios" / "deny"
    destination.mkdir(parents=True)
    sentinel = destination / "operator-data"
    sentinel.write_text("must remain")
    with pytest.raises(
        NegativeLabPreparationError,
        match="destination already exists",
    ):
        prepare_negative_lab(
            NegativeLabConfig(
                source=baseline,
                destination=destination,
                scenario="deny",
            )
        )

    assert snapshot_files(baseline) == baseline_snapshot
    assert sentinel.read_text() == "must remain"


def test_tampered_copy_fails_verification_while_baseline_remains_valid(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    baseline = make_baseline(tmp_path)
    baseline_snapshot = snapshot_files(baseline)
    destination = baseline.parent / "scenarios" / "tampered-audit"
    prepare_negative_lab(
        NegativeLabConfig(
            source=baseline,
            destination=destination,
            scenario="tampered-audit",
        )
    )
    assert {path.name for path in destination.iterdir()} == {
        "audit.key",
        "audit.db",
    }
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in destination.iterdir()
    )

    assert verify_main(["--runtime-dir", str(destination)]) == 1
    tampered_output = capsys.readouterr()
    assert tampered_output.out == "Audit integrity: FAILED\n"
    assert tampered_output.err == ""

    assert verify_main(["--runtime-dir", str(baseline)]) == 0
    baseline_output = capsys.readouterr()
    assert baseline_output.out == "Audit integrity: OK\n"
    assert baseline_output.err == ""
    assert snapshot_files(baseline) == baseline_snapshot


def test_wrong_audit_key_fails_without_disclosing_audit_material(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    baseline = make_baseline(tmp_path)
    destination = baseline.parent / "scenarios" / "wrong-audit-key"
    prepare_negative_lab(
        NegativeLabConfig(
            source=baseline,
            destination=destination,
            scenario="disabled-target",
        )
    )
    original_key = (destination / "audit.key").read_bytes()
    wrong_key = secrets.token_bytes(32)
    while wrong_key == original_key:
        wrong_key = secrets.token_bytes(32)
    (destination / "audit.key").write_bytes(wrong_key)
    (destination / "audit.key").chmod(0o600)

    result = verify_main(["--runtime-dir", str(destination)])

    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert result == 1
    assert captured.out == "Audit integrity: FAILED\n"
    assert captured.err == ""
    for forbidden in (
        AUDIT_EVENT_MARKER,
        "target-001",
        repr(original_key),
        original_key.hex(),
        repr(wrong_key),
        wrong_key.hex(),
        "event_mac",
        "previous_mac",
    ):
        assert forbidden not in combined_output
