"""待审批权限请求的状态仓库。"""

from __future__ import annotations

import time
from typing import Any

try:
    from ..core.sanitizer import safe_json_value, safe_text
    from .state_models import (
        PendingApproval,
        is_valid_request_id,
        is_valid_session_id,
        pending_storage_key,
        safe_inline_text,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_json_value, safe_text
    from persistence.state_models import (
        PendingApproval,
        is_valid_request_id,
        is_valid_session_id,
        pending_storage_key,
        safe_inline_text,
    )


PENDING_CLAIM_FIELDS = ("claimed_by", "claimed_action", "claimed_at")
PENDING_UNCONFIRMED_FIELDS = (
    "decision_unconfirmed_by",
    "decision_unconfirmed_action",
    "decision_unconfirmed_at",
    "decision_unconfirmed_error",
)


class PendingApprovalRepository:
    """只操作状态字典中的 `pending` 区域，不负责加锁和落盘。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def upsert(self, approval: PendingApproval) -> bool:
        """新增或更新一条待审批请求，同时保留已有 claim/unconfirmed 状态。"""
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(approval.session_id, approval.request_id)
        if not key:
            return False
        pending[key] = pending_record(approval, pending.get(key))
        self.data["pending"] = pending
        return True

    def remove(self, session_id: str, request_id: str) -> bool:
        """移除已处理或远端已消失的待审批请求。"""
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        existed = bool(key and key in pending)
        pending.pop(key, None)
        self.data["pending"] = pending
        return existed

    def get(self, session_id: str, request_id: str) -> PendingApproval | None:
        """读取单条待审批请求。"""
        item = _read_dict(self.data.get("pending")).get(
            pending_storage_key(session_id, request_id)
        )
        return pending_from_record(item)

    def list(self) -> list[PendingApproval]:
        """列出所有未 resolved 的待审批请求。"""
        approvals = []
        for item in _read_dict(self.data.get("pending")).values():
            approval = pending_from_record(item)
            if approval is not None:
                approvals.append(approval)
        approvals.sort(key=lambda item: (item.received_at, item.session_id, item.request_id))
        return approvals

    def merge(self, approvals: list[PendingApproval]) -> None:
        """把一批远端审批合并进本地缓存，不删除本地已有项。"""
        pending = _read_dict(self.data.get("pending"))
        for approval in approvals:
            key = pending_storage_key(approval.session_id, approval.request_id)
            if key:
                pending[key] = pending_record(approval, pending.get(key))
        self.data["pending"] = pending

    def replace_for_session(
        self,
        session_id: str,
        approvals: list[PendingApproval],
        *,
        preserve_unconfirmed: bool = True,
    ) -> list[str]:
        """用远端结果替换某个 session 的待审批列表，并返回被删除的 storage key。"""
        if not is_valid_session_id(session_id):
            return []
        pending = _read_dict(self.data.get("pending"))
        incoming = {
            pending_storage_key(approval.session_id, approval.request_id): approval
            for approval in approvals
            if approval.session_id == session_id and is_valid_request_id(approval.request_id)
        }
        removed: list[str] = []
        for key, item in list(pending.items()):
            if not isinstance(item, dict):
                continue
            if _read_str(item.get("session_id")) == session_id and key not in incoming:
                # 远端已经没有这条审批，本地也要删掉并取消对应超时任务。
                removed.append(key)
                pending.pop(key, None)
        for key, approval in incoming.items():
            if key:
                pending[key] = pending_record(
                    approval,
                    pending.get(key),
                    preserve_unconfirmed=preserve_unconfirmed,
                )
        self.data["pending"] = pending
        return removed

    def visible_for_bindings(self, bindings: list[str], max_items: int) -> list[PendingApproval]:
        """筛出当前用户绑定 session 中可见的待审批请求。"""
        if not bindings:
            return []
        approvals = []
        for item in _read_dict(self.data.get("pending")).values():
            if not isinstance(item, dict):
                continue
            if _read_str(item.get("session_id")) not in bindings:
                continue
            approval = pending_from_record(item)
            if approval is not None:
                approvals.append(approval)
        approvals.sort(key=lambda item: (item.received_at, item.request_id))
        if max_items < 1:
            max_items = 1
        return approvals[:max_items]

    def claim(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        """占用一条审批请求，防止并发 allow/deny 或超时 worker 重复处理。"""
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        item = pending.get(key)
        approval = pending_from_record(item)
        if approval is None:
            return None, "当前没有待审批权限，可能已经被处理。"
        claimed_by = _read_str(item.get("claimed_by")) if isinstance(item, dict) else ""
        if claimed_by:
            return None, "该审批请求正在被处理，请稍后执行 /cloudcli pending 刷新。"
        if isinstance(item, dict) and _read_str(item.get("decision_unconfirmed_by")):
            # 发送结果后未确认时不能再次处理，否则可能向 CloudCLI 发送两次冲突决定。
            return (
                None,
                "该审批决定已经发送但尚未确认；请先执行 /cloudcli pending 刷新远端状态后再重试。",
            )
        item["claimed_by"] = safe_text(actor, 200)
        item["claimed_action"] = safe_text(action, 40)
        item["claimed_at"] = time.time()
        pending[key] = item
        self.data["pending"] = pending
        return approval, None

    def release_claim(self, session_id: str, request_id: str, actor: str) -> bool:
        """处理失败或提醒结束后释放当前 actor 的 claim。"""
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        item = pending.get(key)
        if not isinstance(item, dict):
            return False
        if _read_str(item.get("claimed_by")) != actor:
            return False
        for field in PENDING_CLAIM_FIELDS:
            item.pop(field, None)
        pending[key] = item
        self.data["pending"] = pending
        return True

    def mark_decision_unconfirmed(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
        error: str,
    ) -> bool:
        """标记审批决定已发送但远端未确认，等待用户刷新远端状态。"""
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        item = pending.get(key)
        if not isinstance(item, dict):
            return False
        for field in PENDING_CLAIM_FIELDS:
            item.pop(field, None)
        item["decision_unconfirmed_by"] = safe_text(actor, 200)
        item["decision_unconfirmed_action"] = safe_text(action, 40)
        item["decision_unconfirmed_at"] = time.time()
        item["decision_unconfirmed_error"] = safe_text(error, 500)
        pending[key] = item
        self.data["pending"] = pending
        return True


def pending_from_record(item: Any) -> PendingApproval | None:
    """把状态文件中的 dict 还原为 PendingApproval。"""
    if not isinstance(item, dict) or item.get("resolved") is True:
        return None
    session_id = _read_str(item.get("session_id"))
    request_id = _read_str(item.get("request_id"))
    if not is_valid_session_id(session_id) or not is_valid_request_id(request_id):
        return None
    return PendingApproval(
        request_id=request_id,
        session_id=session_id,
        tool_name=_read_str(item.get("tool_name")) or "UnknownTool",
        input_data=item.get("input_data"),
        provider=_read_str(item.get("provider")) or "claude",
        received_at=float(item.get("received_at") or 0),
    )


def pending_record(
    approval: PendingApproval,
    existing: Any = None,
    *,
    preserve_claim: bool = True,
    preserve_unconfirmed: bool = True,
) -> dict[str, Any]:
    """把 PendingApproval 转成可落盘记录，并按需保留处理中状态。"""
    record = {
        "request_id": approval.request_id,
        "session_id": approval.session_id,
        "tool_name": safe_inline_text(approval.tool_name, 120) or "UnknownTool",
        "input_data": safe_json_value(approval.input_data),
        "provider": safe_inline_text(approval.provider, 60) or "claude",
        "received_at": approval.received_at or time.time(),
        "resolved": False,
    }
    if isinstance(existing, dict) and preserve_claim:
        for field in PENDING_CLAIM_FIELDS:
            if existing.get(field):
                record[field] = existing[field]
    if isinstance(existing, dict) and preserve_unconfirmed:
        for field in PENDING_UNCONFIRMED_FIELDS:
            if existing.get(field):
                record[field] = existing[field]
    return record


def normalize_pending_records(value: dict[str, Any]) -> dict[str, Any]:
    """加载状态文件时清洗 pending 记录，丢弃非法键和值。"""
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(item, dict):
            continue
        session_id = _read_str(item.get("session_id"))
        request_id = _read_str(item.get("request_id"))
        if not request_id and isinstance(key, str):
            request_id = key.split("|", 1)[-1]
        storage_key = pending_storage_key(session_id, request_id)
        if not storage_key:
            continue
        normalized = {
            "request_id": request_id,
            "session_id": session_id,
            "tool_name": safe_inline_text(item.get("tool_name"), 120) or "UnknownTool",
            "input_data": safe_json_value(item.get("input_data")),
            "provider": safe_inline_text(item.get("provider"), 60) or "claude",
            "received_at": _parse_timestamp(item.get("received_at")) or time.time(),
            "resolved": bool(item.get("resolved") is True),
        }
        for field in PENDING_UNCONFIRMED_FIELDS:
            if item.get(field):
                normalized[field] = safe_text(item.get(field), 500)
        result[storage_key] = normalized
    return result


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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
