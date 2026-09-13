"""Command-line boundary for the PAM MVP."""

import argparse
from collections.abc import Sequence
from datetime import timedelta
import getpass
from pathlib import Path
import sys

from src.application.access_service import AccessResult
from src.application.authentication_service import AuthenticationFailedError
from src.bootstrap import ApplicationServices, RuntimeSettings, build_application
from src.domain.access import AccessAction, AccessEffect, AccessRequest
from src.domain.authentication import AuthenticatedPrincipal
from src.domain.session import SessionStatus
from src.infrastructure.runtime import SystemClock, UuidIdGenerator
from src.infrastructure.terminal.terminal_mode import raw_terminal_mode


EXIT_SUCCESS = 0
EXIT_INTERNAL_FAILURE = 1
EXIT_AUTHENTICATION_FAILED = 2
EXIT_ACCESS_DENIED = 3
EXIT_SESSION_FAILED = 4
DEFAULT_MAX_SESSION_SECONDS = 30 * 60


class SafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting potentially secret invalid arguments to the terminal."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def build_parser() -> SafeArgumentParser:
    parser = SafeArgumentParser(
        description="PAM MVP local command-line interface",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate_parser = commands.add_parser(
        "validate",
        help="validate explicit runtime configuration and build the application",
    )
    validate_parser.add_argument("--auth-db", type=Path, required=True)
    validate_parser.add_argument("--config-db", type=Path, required=True)
    validate_parser.add_argument("--vault-db", type=Path, required=True)
    validate_parser.add_argument("--audit-db", type=Path, required=True)
    validate_parser.add_argument("--vault-key", type=Path, required=True)
    validate_parser.add_argument("--audit-key", type=Path, required=True)
    validate_parser.add_argument(
        "--max-session-seconds",
        type=float,
        required=True,
    )

    access_parser = commands.add_parser(
        "access",
        help="open an authenticated privileged session",
    )
    access_parser.add_argument("--runtime-dir", type=Path, required=True)
    access_parser.add_argument("--username", required=True)
    access_parser.add_argument("--target-id", required=True)
    access_parser.add_argument(
        "--max-session-seconds",
        type=float,
        default=DEFAULT_MAX_SESSION_SECONDS,
        help="maximum total session duration (default: 1800)",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = build_parser().parse_args(arguments)
    if parsed.command == "validate":
        return _run_validation(parsed)
    return _run_access(parsed)


def _run_validation(parsed: argparse.Namespace) -> int:
    settings = RuntimeSettings(
        auth_db_path=parsed.auth_db,
        config_db_path=parsed.config_db,
        vault_db_path=parsed.vault_db,
        audit_db_path=parsed.audit_db,
        vault_key_path=parsed.vault_key,
        audit_integrity_key_path=parsed.audit_key,
        max_session_duration=timedelta(
            seconds=parsed.max_session_seconds
        ),
    )
    build_application(settings)
    return EXIT_SUCCESS


def _run_access(parsed: argparse.Namespace) -> int:
    runtime_dir = parsed.runtime_dir
    if not _runtime_is_provisioned(runtime_dir):
        print(
            "Runtime is not provisioned. Run the lab provisioning tool first."
        )
        return EXIT_INTERNAL_FAILURE

    try:
        services = build_application(
            _runtime_settings(
                runtime_dir,
                parsed.max_session_seconds,
            )
        )
    except Exception:
        print("Application startup failed. Check the provisioned runtime.")
        return EXIT_INTERNAL_FAILURE

    try:
        pam_password = getpass.getpass("PAM password: ")
    except (EOFError, KeyboardInterrupt):
        print("Authentication failed.")
        return EXIT_AUTHENTICATION_FAILED

    try:
        principal = services.authentication.authenticate(
            parsed.username,
            pam_password,
        )
    except AuthenticationFailedError:
        print("Authentication failed.")
        return EXIT_AUTHENTICATION_FAILED
    except (Exception, KeyboardInterrupt):
        print("Application failure.")
        return EXIT_INTERNAL_FAILURE
    finally:
        pam_password = ""

    try:
        request = AccessRequest(
            id=UuidIdGenerator().new_id(),
            user_id=principal.user_id,
            target_id=parsed.target_id,
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            requested_at=SystemClock().now(),
        )
    except (Exception, KeyboardInterrupt):
        print("Application failure.")
        return EXIT_INTERNAL_FAILURE

    print(f"Authenticated. Requesting access to {parsed.target_id}...")
    try:
        result = _execute_interactive_access(services, principal, request)
    except (Exception, KeyboardInterrupt):
        print("Privileged session failed.")
        return EXIT_SESSION_FAILED

    try:
        return _report_access_result(result)
    except Exception:
        print("Privileged session failed.")
        return EXIT_SESSION_FAILED


def _report_access_result(result: AccessResult) -> int:
    if result.decision.effect is not AccessEffect.ALLOW:
        print("Access denied.")
        return EXIT_ACCESS_DENIED

    if result.session is None or result.session.status is SessionStatus.FAILED:
        print("Privileged session failed.")
        return EXIT_SESSION_FAILED

    if result.session.status is not SessionStatus.CLOSED:
        print("Privileged session failed.")
        return EXIT_SESSION_FAILED

    if result.session.close_reason == "max_duration_exceeded":
        print("Session closed: maximum duration reached.")
    else:
        print("Session closed.")
    return EXIT_SUCCESS


def _execute_interactive_access(
    services: ApplicationServices,
    principal: AuthenticatedPrincipal,
    request: AccessRequest,
) -> AccessResult:
    terminal_io = services.terminal_io
    with raw_terminal_mode(terminal_io.fileno()):
        return services.access.handle(principal, request, terminal_io)


def _runtime_settings(
    runtime_dir: Path,
    max_session_seconds: float,
) -> RuntimeSettings:
    return RuntimeSettings(
        auth_db_path=runtime_dir / "auth.db",
        config_db_path=runtime_dir / "config.db",
        vault_db_path=runtime_dir / "vault.db",
        audit_db_path=runtime_dir / "audit.db",
        vault_key_path=runtime_dir / "vault.key",
        audit_integrity_key_path=runtime_dir / "audit.key",
        max_session_duration=timedelta(seconds=max_session_seconds),
    )


def _runtime_is_provisioned(runtime_dir: Path) -> bool:
    required_files = (
        "vault.key",
        "audit.key",
        "auth.db",
        "config.db",
        "vault.db",
    )
    try:
        return runtime_dir.is_dir() and all(
            (runtime_dir / filename).is_file()
            and (runtime_dir / filename).stat().st_size > 0
            for filename in required_files
        )
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
