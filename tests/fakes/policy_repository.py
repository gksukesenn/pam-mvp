from src.domain.access import AccessAction, AccessPolicy


class FakePolicyRepository:
    def __init__(self, policies: list[AccessPolicy]) -> None:
        self.policies = policies
        self.queries: list[tuple[str, str, AccessAction]] = []
        self.last_result: list[AccessPolicy] | None = None

    def find_matching(
        self,
        user_id: str,
        target_id: str,
        action: AccessAction,
    ) -> list[AccessPolicy]:
        self.queries.append((user_id, target_id, action))
        self.last_result = [
            policy
            for policy in self.policies
            if policy.user_id == user_id
            and policy.target_id == target_id
            and policy.action is action
        ]
        return self.last_result
