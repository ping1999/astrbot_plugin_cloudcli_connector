"""从 AstrBot 事件中提取稳定用户标识。"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any

try:
    from ..persistence.state_models import UserRef, safe_inline_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from persistence.state_models import UserRef, safe_inline_text


async def build_user_ref(event: Any) -> UserRef:
    """构造权限系统使用的 UserRef；缺少 sender_id 时只生成临时不可授权身份。"""
    platform_id = _safe_identity_part(
        await _call_or_attr(event, "get_platform_id"),
        80,
    ) or "unknown-platform"
    sender_id = _safe_identity_part(await _call_or_attr(event, "get_sender_id"), 160)
    session_id = _safe_identity_part(await _call_or_attr(event, "get_session_id"), 160)
    unified_msg_origin = safe_inline_text(getattr(event, "unified_msg_origin", ""), 500)
    if not unified_msg_origin:
        unified_msg_origin = _fallback_origin(platform_id, session_id, sender_id)
    identity_verified = bool(sender_id)

    if not sender_id:
        # 没有可靠 sender_id 时不能放行敏感操作，但仍给用户一个可读的临时标识用于排查。
        identity_scope = session_id or unified_msg_origin or "unknown-session"
        sender_id = f"unidentified:{_stable_digest(str(identity_scope))}"

    raw_display_name = await _call_or_attr(event, "get_sender_name") or str(sender_id)
    display_name = safe_inline_text(raw_display_name, 160) or str(sender_id)
    is_admin = await _is_event_admin(event) if identity_verified else False
    return UserRef(
        user_key=f"{platform_id}:{sender_id}",
        display_name=str(display_name),
        unified_msg_origin=unified_msg_origin,
        is_admin=is_admin,
        identity_verified=identity_verified,
    )


def missing_identity_message(user: UserRef) -> str:
    """生成身份缺失时的统一提示。"""
    return (
        "当前平台事件缺少可靠的发送者 ID，CloudCLI 连接器已拒绝执行需要权限边界的操作。\n"
        f"当前临时标识：{user.user_key}\n"
        "请确认该平台适配器能提供 sender_id，或改用可识别用户身份的平台。"
    )


async def _call_or_attr(event: Any, name: str) -> str:
    """兼容 AstrBot 不同版本中同步/异步方法和普通属性三种形态。"""
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
    """读取 AstrBot 管理员标记，异常时保守地认为不是管理员。"""
    checker = getattr(event, "is_admin", None)
    if isinstance(checker, bool):
        return checker
    if callable(checker):
        try:
            result = checker()
            if inspect.isawaitable(result):
                result = await result
            return bool(result)
        except Exception:  # noqa: BLE001
            pass
    return False


def _stable_digest(value: str) -> str:
    """生成短哈希，避免把不可控原始标识直接拼进临时 user_key。"""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _fallback_origin(platform_id: str, session_id: str, sender_id: str) -> str:
    """在平台没有提供 unified_msg_origin 时构造一个稳定的会话作用域。"""
    scope = session_id or sender_id or "unknown-session"
    return f"{platform_id}:fallback:{_stable_digest(scope)}"


def _safe_identity_part(value: Any, limit: int) -> str:
    """清理身份字段，避免控制字符或超长内容进入状态文件。"""
    return safe_inline_text(value, limit)
