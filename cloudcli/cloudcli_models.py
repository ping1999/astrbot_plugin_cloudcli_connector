"""CloudCLI 响应模型和归一化函数。"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

try:
    from ..core.sanitizer import safe_single_line_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_single_line_text


@dataclass(frozen=True)
class RecentSession:
    """插件内部使用的最近 session 统一结构。"""

    provider: str
    id: str
    summary: str = ""
    messageCount: Any = None
    lastActivity: str = ""
    projectName: str = ""
    projectPath: str = ""

    def to_dict(self) -> dict[str, Any]:
        """转成普通 dict，方便状态缓存和格式化函数处理。"""
        return asdict(self)


@dataclass(frozen=True)
class AbortSessionResult:
    """中止 session 后的确认结果。"""

    session_id: str
    provider: str = ""
    confirmed_inactive: bool = False
    confirmation_error: str = ""


def active_sessions_contains(
    payload: Any,
    session_id: str,
    provider: str = "",
) -> bool:
    """在 CloudCLI 活跃 session 的多种响应形状中判断某个 session 是否仍存在。"""
    if not session_id:
        return False
    sessions = payload.get("sessions") if isinstance(payload, dict) else payload
    if provider and isinstance(sessions, dict):
        return _session_items_contain(sessions.get(provider), session_id)
    return _session_items_contain(sessions, session_id)


def extract_recent_sessions(data: Any, limit: int) -> list[dict[str, Any]]:
    """从项目列表响应中提取所有 provider 的最近 session，并按活动时间倒序截断。"""
    projects = _extract_project_items(data)
    if not isinstance(projects, list):
        raise ValueError("无法解析 CloudCLI 最近 session 响应。")

    result: list[RecentSession] = []
    for project in projects:
        if not isinstance(project, dict):
            continue
        project_name = (
            project.get("displayName")
            or project.get("name")
            or project.get("projectId")
            or project.get("path")
            or ""
        )
        project_path = project.get("fullPath") or project.get("path") or ""
        for provider, field_name in _provider_session_fields():
            sessions = project.get(field_name)
            if not isinstance(sessions, list):
                continue
            for session in sessions:
                item = _normalize_recent_session(
                    session,
                    provider,
                    str(project_name),
                    str(project_path),
                )
                if item:
                    result.append(item)

    result.sort(key=lambda item: item.lastActivity, reverse=True)
    return [item.to_dict() for item in result[: max(1, min(limit, 100))]]


def _extract_project_items(data: Any) -> Any:
    """兼容 `{projects: [...]}`、`{data: [...]}`、`{items: [...]}` 和直接数组。"""
    if not isinstance(data, dict):
        return data
    for key in ("projects", "data", "items"):
        if key in data:
            return data.get(key)
    return None


def _provider_session_fields() -> tuple[tuple[str, str], ...]:
    """CloudCLI 不同 provider 在项目对象中的 session 字段名映射。"""
    return (
        ("claude", "sessions"),
        ("codex", "codexSessions"),
        ("cursor", "cursorSessions"),
        ("gemini", "geminiSessions"),
        ("opencode", "opencodeSessions"),
    )


def _normalize_recent_session(
    session: Any,
    provider: str,
    project_name: str,
    project_path: str,
) -> RecentSession | None:
    """把字符串或 dict 形态的 session 归一化为 RecentSession。"""
    if isinstance(session, str):
        session_id = session
        summary = ""
        message_count = None
        last_activity = ""
    elif isinstance(session, dict):
        session_id = (
            session.get("id")
            or session.get("sessionId")
            or session.get("session_id")
            or session.get("conversationId")
        )
        summary = session.get("summary") or session.get("title") or ""
        message_count = session.get("messageCount") or session.get("message_count")
        last_activity = (
            session.get("lastActivity")
            or session.get("updatedAt")
            or session.get("createdAt")
            or ""
        )
    else:
        return None
    if not session_id:
        return None
    return RecentSession(
        provider=provider,
        id=safe_single_line_text(session_id, 160),
        summary=safe_single_line_text(summary, 240),
        messageCount=message_count,
        lastActivity=safe_single_line_text(last_activity, 80),
        projectName=safe_single_line_text(project_name, 160),
        projectPath=safe_single_line_text(project_path, 500),
    )


def _session_items_contain(value: Any, session_id: str) -> bool:
    """递归扫描嵌套 session 结构，兼容 dict/list/tuple/string。"""
    if isinstance(value, str):
        return value == session_id
    if isinstance(value, list):
        return any(_session_items_contain(item, session_id) for item in value)
    if isinstance(value, tuple):
        return any(_session_items_contain(item, session_id) for item in value)
    if not isinstance(value, dict):
        return False
    for key in ("id", "sessionId", "session_id", "conversationId"):
        if value.get(key) == session_id:
            return True
    return any(_session_items_contain(item, session_id) for item in value.values())
