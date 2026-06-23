from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RecentSession:
    provider: str
    id: str
    summary: str = ""
    messageCount: Any = None
    lastActivity: str = ""
    projectName: str = ""
    projectPath: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AbortSessionResult:
    session_id: str
    provider: str = ""
    confirmed_inactive: bool = False
    confirmation_error: str = ""


def active_sessions_contains(
    payload: Any,
    session_id: str,
    provider: str = "",
) -> bool:
    if not session_id:
        return False
    sessions = payload.get("sessions") if isinstance(payload, dict) else payload
    if provider and isinstance(sessions, dict):
        return _session_items_contain(sessions.get(provider), session_id)
    return _session_items_contain(sessions, session_id)


def extract_recent_sessions(data: Any, limit: int) -> list[dict[str, Any]]:
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
    if not isinstance(data, dict):
        return data
    for key in ("projects", "data", "items"):
        if key in data:
            return data.get(key)
    return None


def _provider_session_fields() -> tuple[tuple[str, str], ...]:
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
        id=str(session_id),
        summary=str(summary) if summary else "",
        messageCount=message_count,
        lastActivity=str(last_activity) if last_activity else "",
        projectName=project_name,
        projectPath=project_path,
    )


def _session_items_contain(value: Any, session_id: str) -> bool:
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
