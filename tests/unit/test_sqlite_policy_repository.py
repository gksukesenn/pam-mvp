import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.application.policy_evaluator import PolicyEvaluator
from src.domain.access import (
    AccessAction,
    AccessEffect,
    AccessPolicy,
    AccessRequest,
)
from src.infrastructure.policy.errors import (
    DuplicatePolicyError,
    MalformedPolicyError,
    PolicyStorageError,
)
from src.infrastructure.policy.sqlite_policy_repository import (
    SQLitePolicyRepository,
)
from src.ports.policy_repository import PolicyRepository


def make_repository(
    tmp_path: Path,
) -> tuple[SQLitePolicyRepository, Path]:
    database_path = tmp_path / "config.db"
    return SQLitePolicyRepository(database_path), database_path


def make_policy(
    policy_id: str = "policy-001",
    *,
    user_id: str = "user-001",
    target_id: str = "target-001",
    effect: AccessEffect = AccessEffect.ALLOW,
) -> AccessPolicy:
    return AccessPolicy(
        id=policy_id,
        user_id=user_id,
        target_id=target_id,
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        effect=effect,
    )


def make_request() -> AccessRequest:
    return AccessRequest(
        id="request-001",
        user_id="user-001",
        target_id="target-001",
        action=AccessAction.OPEN_PRIVILEGED_SESSION,
        requested_at=datetime(2026, 9, 13, tzinfo=UTC),
    )


def read_rows(database_path: Path) -> list[tuple[str, ...]]:
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, user_id, target_id, action, effect
            FROM access_policies
            ORDER BY id
            """
        ).fetchall()


def update_stored_value(
    database_path: Path,
    column: str,
    value: object,
    policy_id: str,
) -> None:
    statements = {
        "id": "UPDATE access_policies SET id = ? WHERE id = ?",
        "action": "UPDATE access_policies SET action = ? WHERE id = ?",
        "effect": "UPDATE access_policies SET effect = ? WHERE id = ?",
    }
    assert column in statements
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(statements[column], (value, policy_id))


def test_store_persists_exact_policy_fields_and_schema(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    policy = make_policy()

    repository.store(policy)

    with closing(sqlite3.connect(database_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(access_policies)"
            ).fetchall()
        ]
    assert columns == ["id", "user_id", "target_id", "action", "effect"]
    assert read_rows(database_path) == [
        (
            "policy-001",
            "user-001",
            "target-001",
            "open_privileged_session",
            "allow",
        )
    ]


def test_policy_schema_contains_no_secret_or_session_content_fields(
    tmp_path: Path,
):
    _, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        columns = {
            row[1].lower()
            for row in connection.execute(
                "PRAGMA table_info(access_policies)"
            ).fetchall()
        }

    forbidden = {
        "credential",
        "password",
        "master_key",
        "brokercredential",
        "terminal_content",
        "transcript",
    }
    assert not any(
        marker in column for marker in forbidden for column in columns
    )


def test_duplicate_policy_id_is_rejected_without_overwriting_original(
    tmp_path: Path,
):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_policy(effect=AccessEffect.DENY))
    original = read_rows(database_path)

    with pytest.raises(
        DuplicatePolicyError,
        match="policy id already exists",
    ):
        repository.store(
            make_policy(
                user_id="replacement-user",
                effect=AccessEffect.ALLOW,
            )
        )

    assert read_rows(database_path) == original


def test_multiple_rules_for_same_subject_target_and_action_are_allowed(
    tmp_path: Path,
):
    repository, _ = make_repository(tmp_path)
    allow = make_policy("policy-allow", effect=AccessEffect.ALLOW)
    deny = make_policy("policy-deny", effect=AccessEffect.DENY)

    repository.store(allow)
    repository.store(deny)

    assert list(
        repository.find_matching(
            "user-001",
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    ) == [allow, deny]


def test_find_matching_returns_exact_domain_policies(tmp_path: Path):
    repository, _ = make_repository(tmp_path)
    expected = make_policy()
    repository.store(expected)
    repository.store(make_policy("other-user", user_id="user-002"))
    repository.store(make_policy("other-target", target_id="target-002"))

    result = list(
        repository.find_matching(
            "user-001",
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    )

    assert result == [expected]
    assert isinstance(result[0], AccessPolicy)
    assert result[0].action is AccessAction.OPEN_PRIVILEGED_SESSION
    assert result[0].effect is AccessEffect.ALLOW


def test_different_stored_action_is_not_returned(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO access_policies (
                    id, user_id, target_id, action, effect
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "future-action-policy",
                    "user-001",
                    "target-001",
                    "future_action",
                    "allow",
                ),
            )

    assert list(
        repository.find_matching(
            "user-001",
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    ) == []


def test_sql_like_ids_are_treated_only_as_values(tmp_path: Path):
    repository, _ = make_repository(tmp_path)
    repository.store(make_policy("ordinary-policy"))
    malicious_user = "' OR 1=1 --"
    malicious_target = "target'; DROP TABLE access_policies; --"
    malicious_policy = make_policy(
        "malicious-looking-policy",
        user_id=malicious_user,
        target_id=malicious_target,
    )
    repository.store(malicious_policy)

    assert list(
        repository.find_matching(
            malicious_user,
            malicious_target,
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    ) == [malicious_policy]
    assert list(
        repository.find_matching(
            malicious_user,
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    ) == []
    assert len(read_rows(tmp_path / "config.db")) == 2


@pytest.mark.parametrize(
    ("policies", "expected_effect", "expected_reason"),
    [
        ([], AccessEffect.DENY, "no_matching_policy"),
        ([make_policy("allow")], AccessEffect.ALLOW, "allow"),
        (
            [make_policy("deny", effect=AccessEffect.DENY)],
            AccessEffect.DENY,
            "deny",
        ),
        (
            [
                make_policy("allow"),
                make_policy("deny", effect=AccessEffect.DENY),
            ],
            AccessEffect.DENY,
            "deny",
        ),
        (
            [
                make_policy("allow-001"),
                make_policy("allow-002"),
            ],
            AccessEffect.ALLOW,
            "allow-001",
        ),
        (
            [
                make_policy(
                    "approval",
                    effect=AccessEffect.REQUIRES_APPROVAL,
                )
            ],
            AccessEffect.DENY,
            "approval_not_supported",
        ),
        (
            [
                make_policy("allow"),
                make_policy(
                    "approval",
                    effect=AccessEffect.REQUIRES_APPROVAL,
                ),
                make_policy("deny", effect=AccessEffect.DENY),
            ],
            AccessEffect.DENY,
            "deny",
        ),
    ],
)
def test_real_repository_preserves_evaluator_precedence(
    tmp_path: Path,
    policies: list[AccessPolicy],
    expected_effect: AccessEffect,
    expected_reason: str,
):
    repository, _ = make_repository(tmp_path)
    for policy in policies:
        repository.store(policy)

    decision = PolicyEvaluator(repository).evaluate(make_request())

    assert decision.effect is expected_effect
    assert decision.reason == expected_reason


def test_unknown_effect_in_matching_row_fails_closed(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_policy())
    update_stored_value(database_path, "effect", "unexpected", "policy-001")

    with pytest.raises(
        MalformedPolicyError,
        match="matching policy contains invalid stored values",
    ):
        PolicyEvaluator(repository).evaluate(make_request())


def test_malformed_matching_row_is_not_silently_discarded(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_policy())
    update_stored_value(database_path, "id", "", "policy-001")

    with pytest.raises(MalformedPolicyError):
        repository.find_matching(
            "user-001",
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )


def test_malformed_action_does_not_accidentally_allow(tmp_path: Path):
    repository, database_path = make_repository(tmp_path)
    repository.store(make_policy())
    update_stored_value(
        database_path,
        "action",
        "malformed_action",
        "policy-001",
    )

    decision = PolicyEvaluator(repository).evaluate(make_request())

    assert decision.effect is AccessEffect.DENY
    assert decision.reason == "no_matching_policy"


def test_unusable_database_path_raises_explicit_storage_error(tmp_path: Path):
    unusable_path = tmp_path / "database-is-a-directory"
    unusable_path.mkdir()

    with pytest.raises(
        PolicyStorageError,
        match="policy database could not be initialized",
    ):
        SQLitePolicyRepository(unusable_path)


def test_storage_failure_during_evaluation_is_not_a_normal_no_match(
    tmp_path: Path,
):
    repository, database_path = make_repository(tmp_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("DROP TABLE access_policies")

    with pytest.raises(
        PolicyStorageError,
        match="policies could not be loaded",
    ):
        PolicyEvaluator(repository).evaluate(make_request())


def test_existing_table_without_required_constraints_is_rejected(
    tmp_path: Path,
):
    database_path = tmp_path / "config.db"
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE access_policies (
                    id TEXT,
                    user_id TEXT,
                    target_id TEXT,
                    action TEXT,
                    effect TEXT
                )
                """
            )

    with pytest.raises(
        PolicyStorageError,
        match="policy database schema is unsupported",
    ):
        SQLitePolicyRepository(database_path)


def test_sqlite_repository_satisfies_policy_repository_contract(
    tmp_path: Path,
):
    repository, _ = make_repository(tmp_path)
    policy_repository: PolicyRepository = repository

    assert list(
        policy_repository.find_matching(
            "user-001",
            "target-001",
            AccessAction.OPEN_PRIVILEGED_SESSION,
        )
    ) == []
