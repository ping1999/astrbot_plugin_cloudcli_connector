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
    user_key: str
    display_name: str
    unified_msg_origin: str
    is_admin: bool = False
    identity_verified: bool = True


@dataclass
class PendingApproval:
    request_id: str
    session_id: str
    tool_name: str
    input_data: Any
    provider: str = "claude"
    received_at: float = 0

    @classmethod
    def from_cloudcli(cls, payload: dict[str, Any]) -> "PendingApproval | None":
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
    return bool(SESSION_ID_RE.fullmatch(value or ""))


def is_valid_request_id(value: str) -> bool:
    return bool(REQUEST_ID_RE.fullmatch(value or ""))


def pending_storage_key(session_id: str, request_id: str) -> str:
    if not is_valid_session_id(session_id) or not is_valid_request_id(request_id):
        return ""
    return f"{session_id}|{request_id}"


def safe_inline_text(value: Any, limit: int) -> str:
    return " ".join(safe_text(value, limit).split())


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


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
