"""审批相关聊天文本格式化。"""

from __future__ import annotations

from typing import Any

try:
    from ..persistence.state_models import PendingApproval
    from .formatting_common import clip_text, render_input
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from persistence.state_models import PendingApproval
    from commands.formatting_common import clip_text, render_input


def format_audit(items: list[dict[str, Any]], limit: int, text_limit: int = 1800) -> str:
    """把审计记录压成短列表，避免一次消息塞入过多历史。"""
    if not items:
        return "当前没有可见的审批审计记录。"
    lines = ["审批审计记录："]
    for item in items[: max(1, limit)]:
        action = item.get("action") or "unknown"
        result = item.get("result") or ""
        user = item.get("display_name") or item.get("user_key") or "unknown"
        tool = item.get("tool_name") or "UnknownTool"
        session_id = item.get("session_id") or ""
        reason = item.get("reason") or ""
        line = f"- {action} [{result}] {tool} session={session_id} by {user}"
        if reason:
            line += f" reason={clip_text(str(reason), 160)}"
        lines.append(line)
    return clip_text("\n".join(lines), text_limit)


def format_pending(approvals: list[PendingApproval], limit: int) -> str:
    """展示待审批列表，并给出 allow/deny 的下一步命令。"""
    if not approvals:
        return "当前绑定的 session 没有待审批权限。"
    lines = ["待审批权限："]
    for index, approval in enumerate(approvals, start=1):
        body = format_approval_body(approval, limit)
        lines.append(f"{index}. {body}")
    lines.append("使用 /cloudcli allow <序号> 或 /cloudcli deny <序号> <原因> 处理。")
    return clip_text("\n\n".join(lines), limit)


def format_push_message(approval: PendingApproval, limit: int) -> str:
    """生成主动推送给审批人的新权限请求提醒。"""
    return clip_text(
        "CloudCLI 有新的权限审批请求：\n"
        f"{format_approval_body(approval, limit)}\n"
        "请使用 /cloudcli pending 查看序号，然后 /cloudcli allow 或 /cloudcli deny 处理。",
        limit,
    )


def format_approval_body(approval: PendingApproval, limit: int) -> str:
    """渲染单条审批详情，包含 session、工具名、请求号和工具输入。"""
    rendered_input = clip_text(render_input(approval.input_data), limit)
    return (
        f"session: {approval.session_id}\n"
        f"tool: {approval.tool_name}\n"
        f"request: {approval.request_id}\n"
        f"input:\n{rendered_input}"
    )
