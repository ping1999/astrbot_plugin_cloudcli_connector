from __future__ import annotations

import hashlib
import inspect
from typing import Any

try:
    from .state import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from state import UserRef


async def build_user_ref(event: Any) -> UserRef:
    platform_id = await _call_or_attr(event, "get_platform_id") or "unknown-platform"
    sender_id = await _call_or_attr(event, "get_sender_id")
    unified_msg_origin = str(getattr(event, "unified_msg_origin", "") or "")
    identity_verified = bool(sender_id)

    if not sender_id:
        session_id = await _call_or_attr(event, "get_session_id") or unified_msg_origin or "unknown-session"
        sender_id = f"unidentified:{_stable_digest(str(session_id))}"

    display_name = await _call_or_attr(event, "get_sender_name") or str(sender_id)
    is_admin = await _is_event_admin(event) if identity_verified else False
    return UserRef(
        user_key=f"{platform_id}:{sender_id}",
        display_name=str(display_name),
        unified_msg_origin=unified_msg_origin,
        is_admin=is_admin,
        identity_verified=identity_verified,
    )


def missing_identity_message(user: UserRef) -> str:
    return (
        "当前平台事件缺少可靠的发送者 ID，CloudCLI 连接器已拒绝执行需要权限边界的操作。\n"
        f"当前临时标识：{user.user_key}\n"
        "请确认该平台适配器能提供 sender_id，或改用可识别用户身份的平台。"
    )


async def _call_or_attr(event: Any, name: str) -> str:
    value = getattr(event, name, None)
    if callable(value):
        try:
            value = value()
            if inspect.isawaitable(value):
                value = await value
        except Exception:  # noqa: BLE001
            return ""
    return str(value or "")


async def _is_event_admin(event: Any) -> bool:
    checker = getattr(event, "is_admin", None)
    if callable(checker):
        try:
            result = checker()
            if inspect.isawaitable(result):
                result = await result
            return bool(result)
        except Exception:  # noqa: BLE001
            pass
    return str(getattr(event, "role", "")).lower() == "admin"


def _stable_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]
