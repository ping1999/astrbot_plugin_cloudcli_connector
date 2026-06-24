"""CloudCLI session、健康检查和聊天记录的展示格式化。"""

from __future__ import annotations

from typing import Any

try:
    from ..core.sanitizer import safe_single_line_text
    from ..core.redaction import redact_text
    from .formatting_common import clip_text, extract_text, read_int, read_str, render_input
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_single_line_text
    from core.redaction import redact_text
    from commands.formatting_common import clip_text, extract_text, read_int, read_str, render_input


def format_sessions(payload: Any) -> str:
    """展示 WebSocket 返回的活跃 session，兼容不同 provider 的字段形状。"""
    sessions = payload.get("sessions") if isinstance(payload, dict) else payload
    if not isinstance(sessions, dict):
        return "无法解析 CloudCLI session 响应。"

    lines = ["CloudCLI 活跃 session："]
    found = False
    for provider in ("claude", "codex", "cursor", "gemini", "opencode"):
        normalized = _normalize_session_items(sessions.get(provider))
        if not normalized:
            continue
        found = True
        lines.append(f"{provider}:")
        lines.extend(f"  - {item}" for item in normalized)
    if not found:
        lines.append("当前没有活跃 session。")
    return "\n".join(lines)


def format_session_overview(
    active_payload: Any | None,
    recent_sessions: list[dict[str, Any]],
    recent_error: str = "",
    text_limit: int = 1800,
) -> str:
    """把活跃 session 和最近 session 合并成一条可绑定参考列表。"""
    lines: list[str] = []
    if active_payload is not None:
        lines.append(format_sessions(active_payload))
    else:
        lines.append("CloudCLI 活跃 session：")
        lines.append("当前没有活跃 session。")

    lines.append("")
    lines.append("最近可绑定 session：")
    if recent_error:
        lines.append(f"读取最近 session 失败：{recent_error}")
    elif not recent_sessions:
        lines.append("没有找到最近 session。")
    else:
        for index, item in enumerate(recent_sessions, start=1):
            lines.append(f"{index}. {_render_recent_session(item)}")
    lines.append("")
    lines.append("绑定示例：/cloudcli bind 1、/cloudcli bind last 或 /cloudcli bind <sessionId>")
    return clip_text("\n".join(lines), text_limit)


def format_health_report(report: dict[str, Any]) -> str:
    """格式化 CloudCLIClient.health_check 返回的分项状态。"""
    base_url = redact_text(str(report.get("base_url") or "(未配置)"))
    lines = [f"CloudCLI 状态：{base_url}"]
    for key, label in (
        ("auth", "认证"),
        ("websocket", "WebSocket"),
        ("rest", "REST"),
        ("agent", "Agent API"),
    ):
        item = report.get(key)
        if not isinstance(item, dict):
            lines.append(f"- {label}: 未知")
            continue
        mark = "OK" if item.get("ok") else "FAIL"
        message = read_str(item.get("message")) or "无详情"
        lines.append(f"- {label}: {mark} - {message}")
    return "\n".join(lines)


def format_bindings(bindings: list[str]) -> str:
    """展示当前用户在当前聊天会话里绑定的 session。"""
    if not bindings:
        return "当前用户没有绑定任何 session。"
    lines = ["当前用户绑定的 session："]
    lines.extend(f"{idx}. {session_id}" for idx, session_id in enumerate(bindings, start=1))
    return "\n".join(lines)


def format_chat_messages(session_id: str, payload: dict[str, Any], limit: int, text_limit: int) -> str:
    """展示 session 最近消息，并按消息数量动态分配每条消息的长度预算。"""
    raw_messages = payload.get("messages")
    if not isinstance(raw_messages, list):
        return "无法解析 CloudCLI session 消息响应。"

    total = read_int(payload.get("total"), len(raw_messages))
    has_more = bool(payload.get("hasMore"))
    if not raw_messages:
        return f"session {session_id} 暂无可展示消息。"

    lines = [f"CloudCLI session 最近消息：{session_id}"]
    lines.append(f"共 {total} 条，展示最近 {min(limit, len(raw_messages))} 条。")
    if has_more:
        lines.append("还有更早消息，可增大 limit 或在 CloudCLI Web UI 查看。")
    lines.append("")
    for index, message in enumerate(raw_messages, start=1):
        rendered = _render_chat_message(message, max(120, text_limit // max(1, len(raw_messages))))
        if rendered:
            lines.append(f"{index}. {rendered}")
    return clip_text("\n".join(lines), text_limit)


def _normalize_session_items(items: Any) -> list[str]:
    """把 CloudCLI 活跃 session 的多种响应形状统一成字符串列表。"""
    if not items:
        return []
    if isinstance(items, list):
        result = []
        for item in items:
            if isinstance(item, str):
                result.append(safe_single_line_text(item, 200))
            elif isinstance(item, dict):
                session_id = item.get("id") or item.get("sessionId") or item.get("session_id")
                status = item.get("status")
                started = item.get("startedAt") or item.get("started_at")
                if session_id:
                    suffix = ""
                    if status:
                        suffix += f" [{safe_single_line_text(status, 80)}]"
                    if started:
                        suffix += f" started={safe_single_line_text(started, 80)}"
                    result.append(f"{safe_single_line_text(session_id, 200)}{suffix}")
        return result
    if isinstance(items, dict):
        return [safe_single_line_text(key, 200) for key in items]
    return []


def _render_recent_session(item: dict[str, Any]) -> str:
    """渲染一条最近 session，序号由上层循环生成。"""
    session_id = safe_single_line_text(item.get("id") or item.get("sessionId") or item.get("session_id"), 200)
    provider = safe_single_line_text(item.get("provider") or "unknown", 80)
    project = clip_text(safe_single_line_text(item.get("projectName") or item.get("projectPath") or "", 500), 180)
    summary = safe_single_line_text(item.get("summary") or "", 240)
    last_activity = clip_text(safe_single_line_text(item.get("lastActivity") or "", 80), 80)
    message_count = item.get("messageCount")

    parts = [f"{session_id} [{provider}]"]
    details = []
    if project:
        details.append(str(project))
    if message_count not in (None, ""):
        details.append(f"{message_count} messages")
    if last_activity:
        details.append(str(last_activity))
    if details:
        parts.append(f"({'; '.join(details)})")
    if summary:
        parts.append(f"- {clip_text(str(summary), 120)}")
    return " ".join(parts)


def _render_chat_message(message: Any, limit: int) -> str:
    """把不同类型的历史消息转成适合聊天窗口阅读的短文本。"""
    if not isinstance(message, dict):
        return clip_text(str(message), limit)

    kind = read_str(message.get("kind")) or read_str(message.get("type")) or "message"
    role = read_str(message.get("role"))
    timestamp = read_str(message.get("timestamp"))
    prefix = _chat_prefix(kind, role)
    if timestamp:
        prefix = f"{prefix} [{timestamp}]"

    if kind == "tool_use":
        tool_name = read_str(message.get("toolName")) or "tool"
        tool_input = render_input(message.get("toolInput"))
        return f"{prefix} {tool_name}\n{clip_text(tool_input, limit)}"
    if kind == "tool_result":
        content = read_str(message.get("content")) or render_input(message.get("toolResult"))
        return f"{prefix}\n{clip_text(content, limit)}"

    content = extract_text(message)
    if not content:
        content = render_input(message)
    return f"{prefix}\n{clip_text(content, limit)}"


def _chat_prefix(kind: str, role: str) -> str:
    """把 CloudCLI 内部消息类型映射成用户能看懂的前缀。"""
    if kind == "thinking":
        return "思考"
    if kind == "tool_use":
        return "工具调用"
    if kind == "tool_result":
        return "工具结果"
    if role == "user":
        return "用户"
    if role == "assistant":
        return "助手"
    return kind
