import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.application.access_service import AccessService
from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.domain.authentication import AuthenticatedPrincipal
from src.domain.privileged_account import CredentialRef, PrivilegedAccount
from src.domain.target import HostKeyFingerprint, Target
from src.infrastructure.config.errors import (
    AmbiguousPrivilegedAccountError,
    ConfigStorageError,
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
from src.ports.session_broker import BrokerCredential
from tests.fakes.access_dependencies import (
    FakeAuditRepository,
    FakeBrokeredSession,
    FakeIdGenerator,
    FakeSessionBroker,
    FakeTerminalIO,
    FakeVault,
    FixedClock,
)

SECRET_MARKERS = (
    b"TARGET-PLAINTEXT-PASSWORD-MARKER",
    b"BROKER-CREDENTIAL-BYTES-MARKER",
    b"ENCRYPTED-CREDENTIAL-CIPHERTEXT-MARKER",
    b"VAULT-MASTER-KEY-MARKER",
    b"AUDIT-INTEGRITY-KEY-MARKER",
    b"TERMINAL-CONTENT-MARKER",
    b"SSH-TRANSCRIPT-MARKER",
)
PRINCIPAL = AuthenticatedPrincipal(user_id="user-001", username="goksu")


def make_access_harness(
    database_path: Path,
    account_count: int = 1,
) -> tuple[
    AccessService,
    SQLiteTargetRepository,
    SQLitePrivilegedAccountRepository,
    FakeVault,
    FakeSessionBroker,
]:
    policy_repository = SQLitePolicyRepository(database_path)
    target_repository = SQLiteTargetRepository(database_path)
    account_repository = SQLitePrivilegedAccountRepository(database_path)
    policy_repository.store(
        AccessPolicy(
            id="policy-001",
            user_id="user-001",
            target_id="target-001",
            action=AccessAction.OPEN_PRIVILEGED_SESSION,
            effect=AccessEffect.ALLOW,
        )
    )
    target_repository.store(
        Target(
            id="target-001",
            name="production-server",
            host="server.example.test",
            port=22,
            expected_host_key=HostKeyFingerprint("SHA256:target-key-001"),
        )
    )
    for index in range(account_count):
        account_repository.store(
            PrivilegedAccount(
                id=f"account-{index + 1:03d}",
                target_id="target-001",
                username="root",
                credential_ref=CredentialRef(
                    f"credential-ref-{index + 1:03d}"
                ),
            )
        )

    vault = FakeVault(BrokerCredential(SECRET_MARKERS[1]))
    broker = FakeSessionBroker(FakeBrokeredSession())
    service = AccessService(
        policy_evaluator=PolicyEvaluator(policy_repository),
        target_repository=target_repository,
        account_repository=account_repository,
        vault=vault,
        session_broker=broker,
        audit_repository=FakeAuditRepository(),
        clock=FixedClock(datetime(2026, 9, 13, tzinfo=UTC)),
        id_generator=FakeIdGenerator(),
        max_session_duration=timedelta(minutes=30),
    )
    return service, target_repository, account_repository, vault, broker


def test_policy_target_and_account_repositories_share_config_db_safely(
    tmp_path: Path,
):
    database_path = tmp_path / "config.db"
    policy_repository = SQLitePolicyRepository(database_path)
    target_repository = SQLiteTargetRepository(database_path)
    account_repository = SQLitePrivilegedAccountRepository(database_path)
    policy = AccessPolicy(
        id="policy-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=AccessEffect.ALLOW,
    )
    target = Target(
        id="target-001",
        name="production-server",
        host="server.example.test",
        port=22,
        expected_host_key=HostKeyFingerprint("SHA256:target-key-001"),
    )
    account = PrivilegedAccount(
        id="account-001",
        target_id=target.id,
        username="root",
        credential_ref=CredentialRef("credential-ref-001"),
    )

    policy_repository.store(policy)
    target_repository.store(target)
    account_repository.store(account)

    with closing(sqlite3.connect(database_path)) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = ? AND name NOT LIKE ?
                """,
                ("table", "sqlite_%"),
            ).fetchall()
        }
    assert tables == {
        "access_policies",
        "targets",
        "privileged_accounts",
    }
    assert list(
        SQLitePolicyRepository(database_path).find_matching(
            policy.user_id,
            policy.target_id,
            policy.action,
        )
    ) == [policy]
    assert SQLiteTargetRepository(database_path).get(target.id) == target
    assert (
        SQLitePrivilegedAccountRepository(
            database_path
        ).find_for_target(target.id)
        == account
    )
    database_bytes = database_path.read_bytes()
    assert all(marker not in database_bytes for marker in SECRET_MARKERS)


def test_ambiguous_real_account_configuration_stops_before_vault_and_broker(
    tmp_path: Path,
):
    database_path = tmp_path / "config.db"
    service, _, _, vault, broker = make_access_harness(
        database_path,
        account_count=2,
    )
    request = AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 13, tzinfo=UTC),
    )

    with pytest.raises(AmbiguousPrivilegedAccountError):
        service.handle(PRINCIPAL, request, FakeTerminalIO())

    assert vault.calls == []
    assert broker.calls == []
    assert SECRET_MARKERS[1] not in database_path.read_bytes()


@pytest.mark.parametrize("broken_table", ["targets", "privileged_accounts"])
def test_real_configuration_storage_failure_stops_before_vault_and_broker(
    tmp_path: Path,
    broken_table: str,
):
    database_path = tmp_path / "config.db"
    service, _, _, vault, broker = make_access_harness(database_path)
    statements = {
        "targets": "DROP TABLE targets",
        "privileged_accounts": "DROP TABLE privileged_accounts",
    }
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(statements[broken_table])
    request = AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 13, tzinfo=UTC),
    )

    with pytest.raises(ConfigStorageError):
        service.handle(PRINCIPAL, request, FakeTerminalIO())

    assert vault.calls == []
    assert broker.calls == []
