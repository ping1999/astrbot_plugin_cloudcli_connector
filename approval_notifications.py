from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApprovalNotificationPlan:
    detailed_targets: tuple[dict[str, Any], ...]


class ApprovalNotificationPolicy:
    def __init__(
        self,
        *,
        approval_allowed_user_keys: frozenset[str],
        approval_require_admin: bool,
    ) -> None:
        self.approval_allowed_user_keys = approval_allowed_user_keys
        self.approval_require_admin = approval_require_admin

    def plan(self, targets: list[dict[str, Any]]) -> ApprovalNotificationPlan:
        detailed = [
            target
            for target in targets
            if target.get("origins") and self.can_receive_details(str(target.get("user_key") or ""))
        ]
        return ApprovalNotificationPlan(detailed_targets=tuple(detailed))

    def can_receive_details(self, user_key: str) -> bool:
        if user_key in self.approval_allowed_user_keys:
            return True
        return not self.approval_require_admin
