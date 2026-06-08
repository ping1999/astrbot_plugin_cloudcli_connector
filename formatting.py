from __future__ import annotations

import json
from typing import Any

try:
    from .state import PendingApproval
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from state import PendingApproval


HELP_TEXT = """CloudCLI Connector 指令：
/cloudcli help：列出插件支持的指令
/cloudcli session：列出 CloudCLI 正在运行和最近可绑定的 session
/cloudcli bind list：列出当前用户绑定的 session
/cloudcli bind <sessionId>：绑定 session
/cloudcli unbind <sessionId>：解绑 session
/cloudcli unbind all：解绑全部 session
/cloudcli chat [sessionId] [limit]：查看 session 最近消息；单绑定时可省略 sessionId
/cloudcli run [选项] <任务>：发起 CloudCLI agent 任务并推送状态
/cloudcli pending：列出已绑定 session 的待审批权限
/cloudcli allow [序号]：允许权限；只有一条时可省略序号
/cloudcli deny [序号] <原因>：拒绝权限；只有一条时可省略序号

run 选项：--project <path>、--github <url>、--session <sessionId>、--provider <claude|cursor|codex|gemini>、--model <model>、--branch <name>、--pr、--no-cleanup
"""


def clip_text(text: str, limit: int) -> str:
    if limit < 20:
        limit = 20
    if len(text) <= limit:
        return text
    return f"{text[: limit - 20]}\n... 已截断 {len(text) - limit + 20} 字符"


def format_sessions(payload: Any) -> str:
    sessions = payload.get("sessions") if isinstance(payload, dict) else payload
    if not isinstance(sessions, dict):
        return "无法解析 CloudCLI session 响应。"

    lines = ["CloudCLI 活跃 session："]
    found = False
    for provider in ("claude", "codex", "cursor", "gemini", "opencode"):
        items = sessions.get(provider)
        normalized = _normalize_session_items(items)
        if not normalized:
            continue
        found = True
        lines.append(f"{provider}:")
        for item in normalized:
            lines.append(f"  - {item}")
    if not found:
        lines.append("当前没有活跃 session。")
    return "\n".join(lines)


def format_session_overview(
    active_payload: Any | None,
    recent_sessions: list[dict[str, Any]],
    recent_error: str = "",
) -> str:
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
            rendered = _render_recent_session(item)
            lines.append(f"{index}. {rendered}")
    lines.append("")
    lines.append("绑定示例：/cloudcli bind <sessionId>")
    return "\n".join(lines)


def format_bindings(bindings: list[str]) -> str:
    if not bindings:
        return "当前用户没有绑定任何 session。"
    lines = ["当前用户绑定的 session："]
    lines.extend(f"{idx}. {session_id}" for idx, session_id in enumerate(bindings, start=1))
    return "\n".join(lines)


def format_chat_messages(session_id: str, payload: dict[str, Any], limit: int, text_limit: int) -> str:
    raw_messages = payload.get("messages")
    if not isinstance(raw_messages, list):
        return "无法解析 CloudCLI session 消息响应。"

    total = _read_int(payload.get("total"), len(raw_messages))
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


def format_agent_start_message(payload: dict[str, Any]) -> str:
    target = payload.get("projectPath") or payload.get("githubUrl") or payload.get("sessionId") or "(unknown)"
    provider = payload.get("provider") or "claude"
    extras = []
    if payload.get("branchName"):
        extras.append(f"branch={payload['branchName']}")
    elif payload.get("createBranch"):
        extras.append("createBranch=true")
    if payload.get("createPR"):
        extras.append("createPR=true")
    suffix = f"\n{', '.join(extras)}" if extras else ""
    return f"已启动 CloudCLI agent 任务：\nprovider: {provider}\ntarget: {target}{suffix}"


def format_agent_status(event: dict[str, Any], text_limit: int) -> str:
    event_type = str(event.get("type") or event.get("event") or "")
    if event_type == "session-id":
        return f"CloudCLI 任务 session：{event.get('sessionId')}"
    if event_type == "status":
        message = _read_str(event.get("message")) or "状态更新"
        project_path = _read_str(event.get("projectPath"))
        if project_path:
            return clip_text(f"CloudCLI 任务状态：{message}\nproject: {project_path}", text_limit)
        return clip_text(f"CloudCLI 任务状态：{message}", text_limit)
    if event_type == "github-branch":
        return f"CloudCLI 已创建/使用分支：{_render_compact_json(event.get('branch'))}"
    if event_type == "github-pr":
        return f"CloudCLI 已创建 PR：{_render_compact_json(event.get('pullRequest'))}"
    if event_type == "github-error":
        return clip_text(f"CloudCLI GitHub 操作失败：{_read_str(event.get('error'))}", text_limit)
    return ""


def format_agent_final(summary: dict[str, Any], text_limit: int) -> str:
    status = "完成" if not summary.get("errors") else "结束但有错误"
    lines = [f"CloudCLI 任务{status}。"]
    if summary.get("sessionId"):
        lines.append(f"session: {summary['sessionId']}")
    if summary.get("projectPath"):
        lines.append(f"project: {summary['projectPath']}")
    if summary.get("branch"):
        lines.append(f"branch: {_render_compact_json(summary['branch'])}")
    if summary.get("pullRequest"):
        lines.append(f"PR: {_render_compact_json(summary['pullRequest'])}")
    errors = summary.get("errors")
    if isinstance(errors, list) and errors:
        lines.append("errors:")
        lines.extend(f"- {clip_text(str(error), 300)}" for error in errors[:5])
    text = _read_str(summary.get("assistantText"))
    if text:
        lines.append("回复摘要：")
        lines.append(clip_text(text, max(200, text_limit - 500)))
    else:
        lines.append("未捕获到文本回复，可在 CloudCLI Web UI 查看完整输出。")
    return clip_text("\n".join(lines), text_limit)


def format_pending(approvals: list[PendingApproval], limit: int) -> str:
    if not approvals:
        return "当前绑定的 session 没有待审批权限。"
    lines = ["待审批权限："]
    for index, approval in enumerate(approvals, start=1):
        body = format_approval_body(approval, limit)
        lines.append(f"{index}. {body}")
    lines.append("使用 /cloudcli allow <序号> 或 /cloudcli deny <序号> <原因> 处理。")
    return "\n\n".join(lines)


def format_push_message(approval: PendingApproval, limit: int) -> str:
    return (
        "CloudCLI 有新的权限审批请求：\n"
        f"{format_approval_body(approval, limit)}\n"
        "请使用 /cloudcli pending 查看序号，然后 /cloudcli allow 或 /cloudcli deny 处理。"
    )


def format_approval_body(approval: PendingApproval, limit: int) -> str:
    rendered_input = _render_input(approval.input_data)
    rendered_input = clip_text(rendered_input, limit)
    return (
        f"session: {approval.session_id}\n"
        f"tool: {approval.tool_name}\n"
        f"request: {approval.request_id}\n"
        f"input:\n{rendered_input}"
    )


def extract_agent_text(event: dict[str, Any]) -> str:
    event_type = str(event.get("type") or event.get("event") or "")
    if event_type in {"content", "text"}:
        return _read_str(event.get("content") or event.get("text"))
    if event_type in {"thinking", "tool_use", "tool_result", "status"}:
        return ""
    if event_type == "response":
        return _extract_text(event.get("data"))
    for key in ("data", "message", "content", "delta"):
        text = _extract_text(event.get(key))
        if text:
            return text
    return ""


def _normalize_session_items(items: Any) -> list[str]:
    if not items:
        return []
    if isinstance(items, list):
        result = []
        for item in items:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                session_id = item.get("id") or item.get("sessionId") or item.get("session_id")
                status = item.get("status")
                started = item.get("startedAt") or item.get("started_at")
                if session_id:
                    suffix = ""
                    if status:
                        suffix += f" [{status}]"
                    if started:
                        suffix += f" started={started}"
                    result.append(f"{session_id}{suffix}")
        return result
    if isinstance(items, dict):
        return [str(key) for key in items]
    return []


def _render_recent_session(item: dict[str, Any]) -> str:
    session_id = item.get("id") or item.get("sessionId") or item.get("session_id")
    provider = item.get("provider") or "unknown"
    project = item.get("projectName") or item.get("projectPath") or ""
    summary = item.get("summary") or ""
    last_activity = item.get("lastActivity") or ""
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
    if not isinstance(message, dict):
        return clip_text(str(message), limit)

    kind = _read_str(message.get("kind")) or _read_str(message.get("type")) or "message"
    role = _read_str(message.get("role"))
    timestamp = _read_str(message.get("timestamp"))
    prefix = _chat_prefix(kind, role)
    if timestamp:
        prefix = f"{prefix} [{timestamp}]"

    if kind == "tool_use":
        tool_name = _read_str(message.get("toolName")) or "tool"
        tool_input = _render_input(message.get("toolInput"))
        return f"{prefix} {tool_name}\n{clip_text(tool_input, limit)}"
    if kind == "tool_result":
        content = _read_str(message.get("content")) or _render_input(message.get("toolResult"))
        return f"{prefix}\n{clip_text(content, limit)}"

    content = _extract_text(message)
    if not content:
        content = _render_input(message)
    return f"{prefix}\n{clip_text(content, limit)}"


def _chat_prefix(kind: str, role: str) -> str:
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


def _extract_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [_extract_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    if not isinstance(value, dict):
        return ""

    if isinstance(value.get("text"), str):
        return value["text"]
    if isinstance(value.get("content"), str):
        return value["content"]
    if isinstance(value.get("content"), list):
        return _extract_text(value["content"])
    message = value.get("message")
    if isinstance(message, dict):
        text = _extract_text(message.get("content"))
        if text:
            return text
    data = value.get("data")
    if isinstance(data, dict):
        text = _extract_text(data)
        if text:
            return text
    delta = value.get("delta")
    if isinstance(delta, dict):
        text = _extract_text(delta)
        if text:
            return text
    return ""


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _render_compact_json(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("url", "html_url"):
            if value.get(key):
                return str(value[key])
        if value.get("number"):
            return f"#{value['number']} {value.get('name') or value.get('title') or ''}".strip()
        if value.get("name"):
            return str(value["name"])
    return clip_text(_render_input(value), 300)


def _render_input(value: Any) -> str:
    if value is None:
        return "(empty)"
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except TypeError:
        return str(value)
