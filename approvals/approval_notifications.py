"""审批通知策略：决定哪些绑定用户能收到包含工具输入的详细通知。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApprovalNotificationPlan:
    """一次审批通知的投递计划。"""

    detailed_targets: tuple[dict[str, Any], ...]


class ApprovalNotificationPolicy:
    """根据审批访问模式过滤通知目标，避免敏感工具输入扩散。"""

    def __init__(
        self,
        *,
        approval_allowed_user_keys: frozenset[str],
        approval_require_admin: bool,
        approval_access_mode: str = "admin_or_allowlist",
        push_details_to_authenticated: bool = False,
    ) -> None:
        self.approval_allowed_user_keys = approval_allowed_user_keys
        self.approval_require_admin = approval_require_admin
        self.approval_access_mode = approval_access_mode
        self.push_details_to_authenticated = push_details_to_authenticated

    def plan(self, targets: list[dict[str, Any]]) -> ApprovalNotificationPlan:
        """从绑定用户列表中挑出可接收详细审批内容的目标。"""
        detailed = [
            target
            for target in targets
            if target.get("origins") and self.can_receive_details(str(target.get("user_key") or ""))
        ]
        return ApprovalNotificationPlan(detailed_targets=tuple(detailed))

    def can_receive_details(self, user_key: str) -> bool:
        """判断单个用户是否可收到审批详情。"""
        if user_key in self.approval_allowed_user_keys:
            return True
        # Detailed proactive pushes include tool input. Keep them narrower than
        # command access unless the operator explicitly opts in.
        if self.push_details_to_authenticated and self.approval_access_mode == "authenticated":
            return True
        return False
