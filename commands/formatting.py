"""格式化函数的聚合出口，兼容历史上从 `commands.formatting` 导入的调用方。"""

from __future__ import annotations

try:
    from .approval_formatting import (
        format_approval_body,
        format_audit,
        format_pending,
        format_push_message,
    )
    from .formatting_common import HELP_TEXT, clip_text
    from .run_formatting import (
        extract_agent_text,
        format_abort_result,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_run_log,
        format_run_tasks,
    )
    from .session_formatting import (
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
        format_sessions,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from commands.approval_formatting import (
        format_approval_body,
        format_audit,
        format_pending,
        format_push_message,
    )
    from commands.formatting_common import HELP_TEXT, clip_text
    from commands.run_formatting import (
        extract_agent_text,
        format_abort_result,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_run_log,
        format_run_tasks,
    )
    from commands.session_formatting import (
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
        format_sessions,
    )


__all__ = [
    "HELP_TEXT",
    "clip_text",
    "extract_agent_text",
    "format_abort_result",
    "format_agent_final",
    "format_agent_start_message",
    "format_agent_status",
    "format_approval_body",
    "format_audit",
    "format_bindings",
    "format_chat_messages",
    "format_health_report",
    "format_pending",
    "format_push_message",
    "format_run_log",
    "format_run_tasks",
    "format_session_overview",
    "format_sessions",
]
