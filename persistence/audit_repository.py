"""审批审计记录仓库。"""

from __future__ import annotations

import time
from typing import Any

try:
    from ..core.sanitizer import safe_text
    from .state_models import PendingApproval, UserRef
    from .user_repository import bindings_for_origin, origin_key
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_text
    from persistence.state_models import PendingApproval, UserRef
    from persistence.user_repository import bindings_for_origin, origin_key


MAX_AUDIT_ITEMS = 500


class AuditRepository:
    """只操作状态字典中的 `audit` 区域，不负责加锁和落盘。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def append(
        self,
        *,
        user: UserRef | None,
        action: str,
        approval: PendingApproval,
        reason: str = "",
        result: str = "sent",
        input_summary: str = "",
    ) -> None:
        """追加一条审批审计记录，并保留最近 MAX_AUDIT_ITEMS 条。"""
        audit = _read_dict_list(self.data.get("audit"))
        audit.append(
            {
                "ts": time.time(),
                "user_key": user.user_key if user else "system",
                "display_name": user.display_name if user else "system",
                "origin": origin_key(user) if user else "",
                "action": safe_text(action, 40),
                "result": safe_text(result, 80),
                "request_id": approval.request_id,
                "session_id": approval.session_id,
                "tool_name": approval.tool_name,
                "provider": approval.provider,
                "reason": safe_text(reason, 500),
                "input_summary": input_summary,
            }
        )
        self.data["audit"] = audit[-MAX_AUDIT_ITEMS:]

    def list(self, user: UserRef, entry: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        """列出当前用户和当前 origin 可见的审计记录。"""
        origin = origin_key(user)
        bindings = set(bindings_for_origin(entry, origin))
        audit = _read_dict_list(self.data.get("audit"))
        items = [
            dict(item)
            for item in audit
            if (
                item.get("user_key") == user.user_key
                and audit_origin_visible(item, entry, origin)
            )
            or (
                item.get("user_key") == "system"
                and bindings
                and item.get("session_id") in bindings
            )
        ]
        items.sort(key=lambda item: float(item.get("ts") or 0), reverse=True)
        return items[: max(1, min(limit, 50))]

    def scrub_sensitive(self, omitted_text: str) -> None:
        """关闭敏感状态持久化时，清除审计中的工具输入摘要。"""
        audit = _read_dict_list(self.data.get("audit"))
        for item in audit:
            if item.get("input_summary"):
                item["input_summary"] = omitted_text
        self.data["audit"] = audit[-MAX_AUDIT_ITEMS:]


def normalize_audit_records(value: Any) -> list[dict[str, Any]]:
    """加载状态文件时清洗审计记录。"""
    records: list[dict[str, Any]] = []
    for item in _read_dict_list(value):
        records.append(
            {
                "ts": _parse_timestamp(item.get("ts")),
                "user_key": safe_text(item.get("user_key"), 200),
                "display_name": safe_text(item.get("display_name"), 160),
                "origin": safe_text(item.get("origin"), 500),
                "action": safe_text(item.get("action"), 40),
                "result": safe_text(item.get("result"), 80),
                "request_id": safe_text(item.get("request_id"), 200),
                "session_id": safe_text(item.get("session_id"), 200),
                "tool_name": safe_text(item.get("tool_name"), 120),
                "provider": safe_text(item.get("provider"), 60) or "claude",
                "reason": safe_text(item.get("reason"), 500),
                "input_summary": safe_text(item.get("input_summary"), 500),
            }
        )
    return records


def audit_origin_visible(item: dict[str, Any], entry: dict[str, Any], origin: str) -> bool:
    """判断旧/新审计记录是否属于当前聊天 origin。"""
    item_origin = _read_str(item.get("origin"))
    if item_origin:
        return item_origin == origin
    origins = _read_list(entry.get("origins"))
    return len(origins) == 1 and origins[0] == origin


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _read_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            from datetime import datetime

            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0
    return 0
