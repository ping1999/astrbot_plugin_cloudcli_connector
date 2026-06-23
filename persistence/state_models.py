"""状态层共享的数据模型和 ID 校验函数。"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

try:
    from ..core.sanitizer import safe_json_value, safe_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_json_value, safe_text


SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")


@dataclass(frozen=True)
class UserRef:
    """插件内部使用的用户身份快照。"""

    user_key: str
    display_name: str
    unified_msg_origin: str
    is_admin: bool = False
    identity_verified: bool = True


@dataclass
class PendingApproval:
    """一条 CloudCLI 权限审批请求。"""

    request_id: str
    session_id: str
    tool_name: str
    input_data: Any
    provider: str = "claude"
    received_at: float = 0

    @classmethod
    def from_cloudcli(cls, payload: dict[str, Any]) -> "PendingApproval | None":
        """从 CloudCLI 原始事件中提取审批对象；缺字段或 ID 非法时返回 None。"""
        request_id = _read_str(payload.get("requestId") or payload.get("request_id"))
        session_id = _read_str(payload.get("sessionId") or payload.get("session_id"))
        if not request_id or not session_id:
            return None
        if not REQUEST_ID_RE.fullmatch(request_id) or not SESSION_ID_RE.fullmatch(session_id):
            return None
        return cls(
            request_id=request_id,
            session_id=session_id,
            tool_name=safe_inline_text(
                payload.get("toolName") or payload.get("tool_name"),
                120,
            )
            or "UnknownTool",
            input_data=safe_json_value(payload.get("input")),
            provider=safe_inline_text(payload.get("provider"), 60) or "claude",
            received_at=_parse_timestamp(payload.get("receivedAt")) or time.time(),
        )


def is_valid_session_id(value: str) -> bool:
    """校验 sessionId，只允许安全短字符串。"""
    return bool(SESSION_ID_RE.fullmatch(value or ""))


def is_valid_request_id(value: str) -> bool:
    """校验权限请求 ID，只允许安全短字符串。"""
    return bool(REQUEST_ID_RE.fullmatch(value or ""))


def pending_storage_key(session_id: str, request_id: str) -> str:
    """生成 pending 字典的稳定键；任一 ID 非法时返回空字符串。"""
    if not is_valid_session_id(session_id) or not is_valid_request_id(request_id):
        return ""
    return f"{session_id}|{request_id}"


def safe_inline_text(value: Any, limit: int) -> str:
    """把文本压成单行，适合 user_key、工具名、provider 等字段。"""
    return " ".join(safe_text(value, limit).split())


def _read_str(value: Any) -> str:
    """只接受字符串，其他类型视为空。"""
    return value if isinstance(value, str) else ""


def _parse_timestamp(value: Any) -> float:
    """读取时间戳；支持数字和 ISO 字符串。"""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            from datetime import datetime

            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0
    return 0
