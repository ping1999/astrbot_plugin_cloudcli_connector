"""CloudCLI agent 任务相关的聊天文本格式化。"""

from __future__ import annotations

from typing import Any

try:
    from .formatting_common import (
        clip_text,
        extract_text,
        read_str,
        render_compact_json,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from commands.formatting_common import (
        clip_text,
        extract_text,
        read_str,
        render_compact_json,
    )


def format_agent_start_message(payload: dict[str, Any], run_id: str = "", text_limit: int = 1800) -> str:
    """任务创建成功后返回给用户的启动摘要。"""
    target = payload.get("projectPath") or payload.get("githubUrl") or payload.get("sessionId") or "(unknown)"
    provider = payload.get("provider") or "claude"
    extras = []
    if run_id:
        extras.append(f"task=#{run_id}")
    if payload.get("branchName"):
        extras.append(f"branch={payload['branchName']}")
    elif payload.get("createBranch"):
        extras.append("createBranch=true")
    if payload.get("createPR"):
        extras.append("createPR=true")
    suffix = f"\n{', '.join(extras)}" if extras else ""
    return clip_text(
        f"已启动 CloudCLI agent 任务：\nprovider: {provider}\ntarget: {target}{suffix}",
        text_limit,
    )


def format_abort_result(result: Any, text_limit: int = 1800) -> str:
    """把中止 session 的确认结果渲染成一句可读说明。"""
    session_id = read_str(getattr(result, "session_id", ""))
    provider = read_str(getattr(result, "provider", ""))
    provider_text = f" provider={provider}" if provider else ""
    if bool(getattr(result, "confirmed_inactive", False)):
        return clip_text(
            f"CloudCLI abort request sent and session is no longer active: {session_id}{provider_text}",
            text_limit,
        )
    confirmation_error = read_str(getattr(result, "confirmation_error", ""))
    suffix = f" confirmation error: {confirmation_error}" if confirmation_error else ""
    return clip_text(
        f"CloudCLI abort request sent but remote stop is not confirmed: {session_id}{provider_text}{suffix}",
        text_limit,
    )


def format_agent_status(event: dict[str, Any], text_limit: int) -> str:
    """挑选值得主动推送的流式事件，普通内容事件由任务日志保存即可。"""
    event_type = str(event.get("type") or event.get("event") or "")
    if event_type == "session-id":
        return clip_text(f"CloudCLI 任务 session：{event.get('sessionId')}", text_limit)
    if event_type == "status":
        message = read_str(event.get("message")) or "状态更新"
        project_path = read_str(event.get("projectPath"))
        if project_path:
            return clip_text(f"CloudCLI 任务状态：{message}\nproject: {project_path}", text_limit)
        return clip_text(f"CloudCLI 任务状态：{message}", text_limit)
    if event_type == "github-branch":
        return clip_text(f"CloudCLI 已创建/使用分支：{render_compact_json(event.get('branch'))}", text_limit)
    if event_type == "github-pr":
        return clip_text(f"CloudCLI 已创建 PR：{render_compact_json(event.get('pullRequest'))}", text_limit)
    if event_type == "github-error":
        return clip_text(f"CloudCLI GitHub 操作失败：{read_str(event.get('error'))}", text_limit)
    return ""


def format_agent_final(summary: dict[str, Any], text_limit: int) -> str:
    """任务结束时生成最终摘要，包括 session、项目、分支、PR、错误和助手文本。"""
    status = "完成" if not summary.get("errors") else "结束但有错误"
    lines = [f"CloudCLI 任务{status}。"]
    if summary.get("sessionId"):
        lines.append(f"session: {summary['sessionId']}")
    if summary.get("projectPath"):
        lines.append(f"project: {summary['projectPath']}")
    if summary.get("branch"):
        lines.append(f"branch: {render_compact_json(summary['branch'])}")
    if summary.get("pullRequest"):
        lines.append(f"PR: {render_compact_json(summary['pullRequest'])}")
    errors = summary.get("errors")
    if isinstance(errors, list) and errors:
        lines.append("errors:")
        lines.extend(f"- {clip_text(str(error), 300)}" for error in errors[:5])
    text = read_str(summary.get("assistantText"))
    if text:
        lines.append("回复摘要：")
        lines.append(clip_text(text, max(200, text_limit - 500)))
    else:
        lines.append("未捕获到文本回复，可在 CloudCLI Web UI 查看完整输出。")
    return clip_text("\n".join(lines), text_limit)


def format_run_tasks(tasks: list[dict[str, Any]], limit: int, text_limit: int = 1800) -> str:
    """渲染当前用户在当前聊天会话中可见的任务列表。"""
    if not tasks:
        return "当前用户还没有 CloudCLI 任务。"
    lines = ["CloudCLI 任务："]
    for item in tasks[: max(1, limit)]:
        run_id = item.get("id") or "?"
        status = item.get("status") or "unknown"
        provider = item.get("provider") or "claude"
        target = item.get("target") or item.get("project_path") or item.get("github_url") or item.get("session_id") or "(unknown)"
        session_id = item.get("session_id") or ""
        suffix = f" session={session_id}" if session_id else ""
        lines.append(f"#{run_id} [{status}] {provider} -> {target}{suffix}")
    lines.append("查看日志：/cloudcli run log <任务编号>；取消：/cloudcli run cancel <任务编号>")
    return clip_text("\n".join(lines), text_limit)


def format_run_log(task: dict[str, Any], text_limit: int) -> str:
    """渲染单个任务的关键信息和最近日志。"""
    run_id = task.get("id") or "?"
    status = task.get("status") or "unknown"
    lines = [f"CloudCLI 任务 #{run_id} 日志："]
    lines.append(f"status: {status}")
    lines.append(f"provider: {task.get('provider') or 'claude'}")
    target = task.get("target") or task.get("project_path") or task.get("github_url") or task.get("session_id") or ""
    if target:
        lines.append(f"target: {target}")
    if task.get("session_id"):
        lines.append(f"session: {task['session_id']}")
    if task.get("error"):
        lines.append(f"error: {task['error']}")
    log_items = task.get("log")
    lines.append("")
    if isinstance(log_items, list) and log_items:
        for item in log_items[-20:]:
            if isinstance(item, dict):
                text = read_str(item.get("text"))
                if text:
                    lines.append(f"- {clip_text(text, 300)}")
    else:
        lines.append("暂无日志。")
    return clip_text("\n".join(lines), text_limit)


def extract_agent_text(event: dict[str, Any]) -> str:
    """从流式事件中提取可保存的助手正文，过滤 thinking/status/tool 这类噪声。"""
    event_type = str(event.get("type") or event.get("event") or "")
    if event_type in {"content", "text"}:
        return read_str(event.get("content") or event.get("text"))
    if event_type in {"thinking", "tool_use", "tool_result", "status"}:
        return ""
    if event_type == "response":
        return extract_text(event.get("data"))
    for key in ("data", "message", "content", "delta"):
        text = extract_text(event.get(key))
        if text:
            return text
    return ""
