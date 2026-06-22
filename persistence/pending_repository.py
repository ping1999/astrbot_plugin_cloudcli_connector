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


class PendingApprovalRepository:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def upsert(self, approval: PendingApproval) -> bool:
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(approval.session_id, approval.request_id)
        if not key:
            return False
        pending[key] = pending_record(approval, pending.get(key))
        self.data["pending"] = pending
        return True

    def remove(self, session_id: str, request_id: str) -> bool:
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        existed = bool(key and key in pending)
        pending.pop(key, None)
        self.data["pending"] = pending
        return existed

    def get(self, session_id: str, request_id: str) -> PendingApproval | None:
        item = _read_dict(self.data.get("pending")).get(
            pending_storage_key(session_id, request_id)
        )
        return pending_from_record(item)

    def list(self) -> list[PendingApproval]:
        approvals = []
        for item in _read_dict(self.data.get("pending")).values():
            approval = pending_from_record(item)
            if approval is not None:
                approvals.append(approval)
        approvals.sort(key=lambda item: (item.received_at, item.session_id, item.request_id))
        return approvals

    def merge(self, approvals: list[PendingApproval]) -> None:
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
    ) -> list[str]:
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
                removed.append(key)
                pending.pop(key, None)
        for key, approval in incoming.items():
            if key:
                pending[key] = pending_record(approval, pending.get(key))
        self.data["pending"] = pending
        return removed

    def visible_for_bindings(self, bindings: list[str], max_items: int) -> list[PendingApproval]:
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
        pending = _read_dict(self.data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        item = pending.get(key)
        approval = pending_from_record(item)
        if approval is None:
            return None, "当前没有待审批权限，可能已经被处理。"
        claimed_by = _read_str(item.get("claimed_by")) if isinstance(item, dict) else ""
        if claimed_by:
            return None, "该审批请求正在被处理，请稍后执行 /cloudcli pending 刷新。"
        item["claimed_by"] = safe_text(actor, 200)
        item["claimed_action"] = safe_text(action, 40)
        item["claimed_at"] = time.time()
        pending[key] = item
        self.data["pending"] = pending
        return approval, None

    def release_claim(self, session_id: str, request_id: str, actor: str) -> bool:
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


def pending_from_record(item: Any) -> PendingApproval | None:
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


def pending_record(approval: PendingApproval, existing: Any = None) -> dict[str, Any]:
    record = {
        "request_id": approval.request_id,
        "session_id": approval.session_id,
        "tool_name": safe_inline_text(approval.tool_name, 120) or "UnknownTool",
        "input_data": safe_json_value(approval.input_data),
        "provider": safe_inline_text(approval.provider, 60) or "claude",
        "received_at": approval.received_at or time.time(),
        "resolved": False,
    }
    if isinstance(existing, dict):
        for field in PENDING_CLAIM_FIELDS:
            if existing.get(field):
                record[field] = existing[field]
    return record


def normalize_pending_records(value: dict[str, Any]) -> dict[str, Any]:
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
