from collections.abc import Collection
from typing import Protocol

from src.domain.access import AccessAction, AccessPolicy


class PolicyRepository(Protocol):
    def find_matching(
        self,
        user_id: str,
        target_id: str,
        action: AccessAction,
    ) -> Collection[AccessPolicy]: ...
