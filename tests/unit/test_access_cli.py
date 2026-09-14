import argparse
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
import sqlite3
from types import SimpleNamespace

import pytest

import src.main as main_module
from src.application.access_service import AccessResult
from src.application.authentication_service import AuthenticationFailedError
from src.domain.access import AccessAction, AccessDecision, AccessEffect
from src.domain.audit import AuditEventType
from src.domain.authentication import AuthenticatedPrincipal
from src.domain.session import Session, SessionStatus
from src.infrastructure.audit.sqlite_audit_repository import (
    SQLiteAuditRepository,
)
from src.infrastructure.security.file_key_provider import FileKeyProvider
from src.ports.session_broker import RelayOutcome
from src.tools.provision_lab import LabProvisioningConfig, provision_lab


PAM_PASSWORD = "CLI-PAM-PASSWORD-SECRET-MARKER"
TARGET_PASSWORD = "CLI-TARGET-PASSWORD-SECRET-MARKER"
NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)


class FakeAuthentication:
    def __init__(
        self,
        events: list[str],
        principal: AuthenticatedPrincipal | None = None,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.principal = principal or AuthenticatedPrincipal(
            user_id="authenticated-user-777",
            username="goksu",
        )
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> AuthenticatedPrincipal:
        self.events.append("authenticate")
        self.calls.append((username, password))
        if self.error is not None:
            raise self.error
        return self.principal


class FakeTerminalIO:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def fileno(self) -> int:
        self.events.append("fileno")
        return 17


class FakeAccess:
    def __init__(
        self,
        events: list[str],
        result: AccessResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.events = events
        self.result = result
        self.error = error
        self.calls: list[tuple[object, object, object]] = []

    def handle(
        self,
        principal: object,
        request: object,
        terminal_io: object,
    ) -> AccessResult:
        self.events.append("access")
        self.calls.append((principal, request, terminal_io))
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def make_session(
    status: SessionStatus,
    reason: str,
) -> Session:
    return Session(
        id="session-001",
        request_id="request-001",
        user_id="authenticated-user-777",
        target_id="target-001",
        account_id="account-001",
        status=status,
        started_at=NOW,
        ended_at=NOW,
        close_reason=reason,
    )


def allow_result(
    status: SessionStatus = SessionStatus.CLOSED,
    reason: str = "relay_completed",
) -> AccessResult:
    return AccessResult(
        decision=AccessDecision(
            effect=AccessEffect.ALLOW,
            reason="policy-001",
        ),
        session=make_session(status, reason),
    )


def prepare_runtime(tmp_path: Path) -> Path:
    runtime_dir = tmp_path / "runtime" / "lab"
    runtime_dir.mkdir(parents=True, mode=0o700)
    runtime_dir.chmod(0o700)
    for filename in (
        "vault.key",
        "audit.key",
        "auth.db",
        "config.db",
        "vault.db",
    ):
        (runtime_dir / filename).write_bytes(b"test-placeholder")
    return runtime_dir


def test_access_rejects_symlinked_runtime_before_composition_or_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    actual_runtime = prepare_runtime(tmp_path)
    linked_runtime = tmp_path / "linked-runtime"
    linked_runtime.symlink_to(actual_runtime, target_is_directory=True)
    monkeypatch.setattr(
        main_module,
        "build_application",
        lambda settings: pytest.fail("must not build from symlinked runtime"),
    )
    monkeypatch.setattr(
        main_module.getpass,
        "getpass",
        lambda prompt: pytest.fail("must not prompt for symlinked runtime"),
    )

    result = main_module.main(access_arguments(linked_runtime))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert captured.out == (
        "Runtime is not provisioned. Run the lab provisioning tool first.\n"
    )
    assert captured.err == ""


def test_access_rejects_runtime_with_group_permissions_before_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = prepare_runtime(tmp_path)
    runtime_dir.chmod(0o750)
    monkeypatch.setattr(
        main_module,
        "build_application",
        lambda settings: pytest.fail("must not build from unsafe runtime"),
    )
    monkeypatch.setattr(
        main_module.getpass,
        "getpass",
        lambda prompt: pytest.fail("must not prompt for unsafe runtime"),
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert captured.out == (
        "Runtime is not provisioned. Run the lab provisioning tool first.\n"
    )
    assert captured.err == ""


def access_arguments(runtime_dir: Path) -> list[str]:
    return [
        "access",
        "--runtime-dir",
        str(runtime_dir),
        "--username",
        "goksu",
        "--target-id",
        "target-001",
    ]


def install_cli_fakes(
    monkeypatch: pytest.MonkeyPatch,
    runtime_dir: Path,
    authentication: FakeAuthentication,
    access: FakeAccess,
    terminal_io: FakeTerminalIO,
    events: list[str],
) -> list[object]:
    received_settings: list[object] = []

    def build(settings: object) -> object:
        events.append("build")
        received_settings.append(settings)
        return SimpleNamespace(
            authentication=authentication,
            access=access,
            terminal_io=terminal_io,
        )

    def read_password(prompt: str) -> str:
        assert prompt == "PAM password: "
        events.append("getpass")
        return PAM_PASSWORD

    @contextmanager
    def fake_raw_mode(file_descriptor: int):
        assert file_descriptor == 17
        events.append("raw_enter")
        try:
            yield
        finally:
            events.append("raw_exit")

    monkeypatch.setattr(main_module, "build_application", build)
    monkeypatch.setattr(main_module.getpass, "getpass", read_password)
    monkeypatch.setattr(main_module, "raw_terminal_mode", fake_raw_mode)
    assert runtime_dir.is_dir()
    return received_settings


def test_authenticated_access_binds_principal_and_restores_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = prepare_runtime(tmp_path)
    events: list[str] = []
    authentication = FakeAuthentication(events)
    access = FakeAccess(events, result=allow_result())
    terminal_io = FakeTerminalIO(events)
    received_settings = install_cli_fakes(
        monkeypatch,
        runtime_dir,
        authentication,
        access,
        terminal_io,
        events,
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_SUCCESS
    assert events == [
        "build",
        "getpass",
        "authenticate",
        "fileno",
        "raw_enter",
        "access",
        "raw_exit",
    ]
    assert authentication.calls == [("goksu", PAM_PASSWORD)]
    assert len(access.calls) == 1
    principal, request, received_terminal = access.calls[0]
    assert principal == authentication.principal
    assert request.user_id == authentication.principal.user_id
    assert request.target_id == "target-001"
    assert request.action is AccessAction.OPEN_PRIVILEGED_SESSION
    assert request.requested_at.tzinfo is not None
    assert received_terminal is terminal_io
    assert received_settings == [
        main_module.RuntimeSettings(
            auth_db_path=runtime_dir / "auth.db",
            config_db_path=runtime_dir / "config.db",
            vault_db_path=runtime_dir / "vault.db",
            audit_db_path=runtime_dir / "audit.db",
            vault_key_path=runtime_dir / "vault.key",
            audit_integrity_key_path=runtime_dir / "audit.key",
            max_session_duration=timedelta(minutes=30),
        )
    ]
    assert captured.out.splitlines() == [
        "Authenticated. Requesting access to target-001...",
        "Session closed.",
    ]
    combined_output = captured.out + captured.err
    assert PAM_PASSWORD not in combined_output
    assert TARGET_PASSWORD not in combined_output


def test_failed_authentication_never_enters_raw_mode_or_calls_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = prepare_runtime(tmp_path)
    events: list[str] = []
    authentication = FakeAuthentication(
        events,
        error=AuthenticationFailedError("unknown, inactive, or wrong"),
    )
    access = FakeAccess(events, result=allow_result())
    terminal_io = FakeTerminalIO(events)
    install_cli_fakes(
        monkeypatch,
        runtime_dir,
        authentication,
        access,
        terminal_io,
        events,
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_AUTHENTICATION_FAILED
    assert events == ["build", "getpass", "authenticate"]
    assert access.calls == []
    assert captured.out == "Authentication failed.\n"
    assert captured.err == ""
    assert PAM_PASSWORD not in captured.out + captured.err
    assert "unknown" not in captured.out + captured.err
    assert "inactive" not in captured.out + captured.err
    assert "wrong" not in captured.out + captured.err


@pytest.mark.parametrize(
    ("access_result", "expected_code", "expected_message"),
    [
        (
            AccessResult(
                decision=AccessDecision(
                    effect=AccessEffect.DENY,
                    reason="sensitive-internal-denial-reason",
                ),
                session=None,
            ),
            main_module.EXIT_ACCESS_DENIED,
            "Access denied.",
        ),
        (
            allow_result(SessionStatus.FAILED, "broker_open_failed"),
            main_module.EXIT_SESSION_FAILED,
            "Privileged session failed.",
        ),
        (
            allow_result(SessionStatus.CLOSED, "max_duration_exceeded"),
            main_module.EXIT_SUCCESS,
            "Session closed: maximum duration reached.",
        ),
    ],
)
def test_access_results_map_to_safe_exit_codes_and_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    access_result: AccessResult,
    expected_code: int,
    expected_message: str,
):
    runtime_dir = prepare_runtime(tmp_path)
    events: list[str] = []
    authentication = FakeAuthentication(events)
    access = FakeAccess(events, result=access_result)
    terminal_io = FakeTerminalIO(events)
    install_cli_fakes(
        monkeypatch,
        runtime_dir,
        authentication,
        access,
        terminal_io,
        events,
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == expected_code
    assert len(access.calls) == 1
    assert events[-3:] == ["raw_enter", "access", "raw_exit"]
    assert captured.out.splitlines()[-1] == expected_message
    assert "sensitive-internal-denial-reason" not in captured.out
    assert "broker_open_failed" not in captured.out


def test_access_exception_is_redacted_and_terminal_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = prepare_runtime(tmp_path)
    events: list[str] = []
    authentication = FakeAuthentication(events)
    leaked_detail = "Paramiko SQLite failure with target credential"
    access = FakeAccess(events, error=RuntimeError(leaked_detail))
    terminal_io = FakeTerminalIO(events)
    install_cli_fakes(
        monkeypatch,
        runtime_dir,
        authentication,
        access,
        terminal_io,
        events,
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_SESSION_FAILED
    assert len(access.calls) == 1
    assert events[-3:] == ["raw_enter", "access", "raw_exit"]
    assert captured.out.splitlines()[-1] == "Privileged session failed."
    assert leaked_detail not in captured.out + captured.err


def test_unprovisioned_runtime_fails_without_prompt_build_or_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = tmp_path / "missing-runtime"
    monkeypatch.setattr(
        main_module,
        "build_application",
        lambda settings: pytest.fail("must not build an unprovisioned runtime"),
    )
    monkeypatch.setattr(
        main_module.getpass,
        "getpass",
        lambda prompt: pytest.fail("must not prompt for an invalid runtime"),
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert "Run the lab provisioning tool first." in captured.out
    assert captured.err == ""
    assert not runtime_dir.exists()


def test_startup_failure_does_not_print_infrastructure_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = prepare_runtime(tmp_path)
    leaked_detail = "SQLite vault.key ciphertext initialization failure"
    monkeypatch.setattr(
        main_module,
        "build_application",
        lambda settings: (_ for _ in ()).throw(RuntimeError(leaked_detail)),
    )
    monkeypatch.setattr(
        main_module.getpass,
        "getpass",
        lambda prompt: pytest.fail("startup failure must not prompt"),
    )

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_INTERNAL_FAILURE
    assert captured.out == (
        "Application startup failed. Check the provisioned runtime.\n"
    )
    assert captured.err == ""
    assert leaked_detail not in captured.out + captured.err


def test_access_parser_has_no_secret_or_spoofable_identity_options(
    capsys: pytest.CaptureFixture[str],
):
    parser = main_module.build_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    access_parser = subparsers.choices["access"]
    option_strings = {
        option
        for action in access_parser._actions
        for option in action.option_strings
    }

    assert option_strings == {
        "-h",
        "--help",
        "--runtime-dir",
        "--username",
        "--target-id",
        "--max-session-seconds",
    }
    assert "--user-id" not in option_strings
    assert "--password" not in option_strings
    assert "--target-password" not in option_strings
    assert "--credential" not in option_strings
    assert "--vault-key" not in option_strings
    assert "--audit-key" not in option_strings

    for forbidden_option in (
        "--user-id",
        "--password",
        "--target-password",
        "--credential",
        "--vault-key",
        "--audit-key",
    ):
        with pytest.raises(SystemExit) as raised:
            parser.parse_args(
                [
                    "access",
                    "--runtime-dir",
                    "runtime/lab",
                    "--username",
                    "goksu",
                    "--target-id",
                    "target-001",
                    forbidden_option,
                    PAM_PASSWORD,
                ]
            )
        assert raised.value.code == 2
    captured = capsys.readouterr()
    assert PAM_PASSWORD not in captured.out + captured.err


def test_access_cli_uses_real_composition_through_final_broker_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    runtime_dir = tmp_path / "runtime" / "lab"
    provisioned_secrets = iter((PAM_PASSWORD, TARGET_PASSWORD))
    provision_lab(
        LabProvisioningConfig(runtime_dir=runtime_dir),
        lambda prompt: next(provisioned_secrets),
    )
    original_build_application = main_module.build_application
    built_services: list[object] = []
    broker_calls: list[tuple[object, object, bytes]] = []
    relay_calls: list[tuple[object, timedelta]] = []
    close_calls: list[None] = []
    access_prompts: list[str] = []

    class BrokeredSession:
        def relay(
            self,
            terminal_io: object,
            max_duration: timedelta,
        ) -> RelayOutcome:
            relay_calls.append((terminal_io, max_duration))
            return RelayOutcome.COMPLETED

        def close(self) -> None:
            close_calls.append(None)

    class Broker:
        def open_session(
            self,
            target: object,
            privileged_account: object,
            credential: object,
        ) -> BrokeredSession:
            broker_calls.append(
                (target, privileged_account, credential.as_bytes())
            )
            return BrokeredSession()

    def build_without_network(settings: object) -> object:
        services = original_build_application(settings)
        services.access._session_broker = Broker()
        built_services.append(services)
        return services

    def reject_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("automated CLI test must not connect to SSH")

    def read_pam_password(prompt: str) -> str:
        access_prompts.append(prompt)
        return PAM_PASSWORD

    @contextmanager
    def fake_raw_mode(file_descriptor: int):
        assert file_descriptor == 0
        yield

    monkeypatch.setattr(main_module, "build_application", build_without_network)
    monkeypatch.setattr(main_module.getpass, "getpass", read_pam_password)
    monkeypatch.setattr(main_module, "raw_terminal_mode", fake_raw_mode)
    monkeypatch.setattr(socket, "create_connection", reject_network)

    result = main_module.main(access_arguments(runtime_dir))

    captured = capsys.readouterr()
    assert result == main_module.EXIT_SUCCESS
    assert access_prompts == ["PAM password: "]
    assert len(built_services) == 1
    services = built_services[0]
    assert len(broker_calls) == 1
    target, account, credential_bytes = broker_calls[0]
    assert target.id == "target-001"
    assert target.name == "linux-server-1"
    assert target.host == "192.168.122.227"
    assert target.port == 22
    assert account.id == "account-001"
    assert account.target_id == target.id
    assert account.username == "pamadmin"
    assert account.credential_ref.id == "cred-001"
    assert credential_bytes == TARGET_PASSWORD.encode()
    assert relay_calls == [
        (services.terminal_io, timedelta(minutes=30))
    ]
    assert close_calls == [None]

    with sqlite3.connect(runtime_dir / "audit.db") as connection:
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM audit_events ORDER BY sequence_no"
            ).fetchall()
        ]
    assert event_types == [
        AuditEventType.ACCESS_ALLOWED.value,
        AuditEventType.SESSION_OPENING.value,
        AuditEventType.SESSION_ACTIVE.value,
        AuditEventType.SESSION_CLOSED.value,
    ]
    SQLiteAuditRepository(
        runtime_dir / "audit.db",
        FileKeyProvider(runtime_dir / "audit.key"),
    ).verify_integrity()
    combined_output = captured.out + captured.err
    assert PAM_PASSWORD not in combined_output
    assert TARGET_PASSWORD not in combined_output
    assert "BrokerCredential" not in combined_output
    assert captured.out.splitlines()[-1] == "Session closed."
