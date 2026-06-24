"""Privacy policy for data written to the local state file."""

from __future__ import annotations

from typing import Any

try:
    from ..core.sanitizer import compact_json, safe_text
    from .state_models import PendingApproval
    from .user_repository import normalize_session_index_items
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import compact_json, safe_text
    from persistence.state_models import PendingApproval
    from persistence.user_repository import normalize_session_index_items


OMITTED_SENSITIVE_TEXT = "[omitted by persist_sensitive_state=false]"
OMITTED_SENSITIVE_INPUT = {
    "notice": "approval input is kept only in memory unless persist_sensitive_state is enabled"
}


class StoragePrivacyPolicy:
    """Centralize what may be persisted when sensitive state storage is disabled."""

    def __init__(self, *, persist_sensitive_state: bool) -> None:
        self.persist_sensitive_state = persist_sensitive_state

    def approval_for_storage(self, approval: PendingApproval) -> PendingApproval:
        """Return a pending approval record safe to write to disk."""
        if self.persist_sensitive_state:
            return approval
        return PendingApproval(
            request_id=approval.request_id,
            session_id=approval.session_id,
            tool_name=approval.tool_name,
            input_data=dict(OMITTED_SENSITIVE_INPUT),
            provider=approval.provider,
            received_at=approval.received_at,
        )

    def sensitive_text_for_storage(self, value: Any, *, limit: int = 1200) -> str:
        """Persist free-form text only when explicitly configured to do so."""
        if self.persist_sensitive_state:
            return safe_text(value, limit)
        text = value if isinstance(value, str) else str(value or "")
        return f"{OMITTED_SENSITIVE_TEXT}; chars={len(text)}"

    def target_for_storage(self, value: Any, *, limit: int = 500) -> str:
        """Project paths and repo URLs reveal local/private context, so omit them by default."""
        if self.persist_sensitive_state:
            return safe_text(value, limit)
        return OMITTED_SENSITIVE_TEXT if value else ""

    def approval_input_summary_for_storage(self, approval: PendingApproval) -> str:
        """Store an approval input summary only when the operator opts in."""
        if self.persist_sensitive_state:
            return safe_text(compact_json(approval.input_data), 500)
        return OMITTED_SENSITIVE_TEXT

    def run_summary_for_storage(self, summary: dict[str, Any]) -> dict[str, Any]:
        """Remove run output and target metadata from durable state by default."""
        if self.persist_sensitive_state:
            return summary
        stored = dict(summary)
        for key in ("projectPath", "branch", "pullRequest", "assistantText"):
            if stored.get(key):
                stored[key] = OMITTED_SENSITIVE_TEXT
        if stored.get("errors"):
            stored["errors"] = OMITTED_SENSITIVE_TEXT
        return stored

    def run_event_for_storage(self, event: Any, *, limit: int = 1200) -> str:
        """Run logs may contain paths, repo URLs, prompts, or model output."""
        if self.persist_sensitive_state:
            return safe_text(event, limit)
        return OMITTED_SENSITIVE_TEXT if event else ""

    def session_index_for_storage(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Persist only stable session lookup fields unless full sensitive state is enabled."""
        if self.persist_sensitive_state:
            return sessions
        stored_sessions: list[dict[str, Any]] = []
        for item in sessions:
            if not isinstance(item, dict):
                continue
            stored_sessions.append(
                {
                    "id": item.get("id") or item.get("sessionId") or item.get("session_id") or "",
                    "provider": item.get("provider") or "",
                    "lastActivity": item.get("lastActivity") or "",
                }
            )
        return normalize_session_index_items(stored_sessions)
