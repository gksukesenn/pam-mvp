from src.domain.access import AccessAction, AccessPolicy


class FakePolicyRepository:
    def __init__(
        self,
        policies: list[AccessPolicy],
        call_log: list[str] | None = None,
    ) -> None:
        self.policies = policies
        self.call_log = call_log
        self.queries: list[tuple[str, str, AccessAction]] = []
        self.last_result: list[AccessPolicy] | None = None

    def find_matching(
        self,
        user_id: str,
        target_id: str,
        action: AccessAction,
    ) -> list[AccessPolicy]:
        if self.call_log is not None:
            self.call_log.append("policy_repository.find_matching")
        self.queries.append((user_id, target_id, action))
        self.last_result = [
            policy
            for policy in self.policies
            if policy.user_id == user_id
            and policy.target_id == target_id
            and policy.action is action
        ]
        return self.last_result
