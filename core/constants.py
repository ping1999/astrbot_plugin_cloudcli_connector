"""插件范围内共享的常量。"""

from __future__ import annotations


PLUGIN_NAME = "astrbot_plugin_cloudcli_connector"
MAX_DENY_REASON_LEN = 500
RUN_PROVIDERS = frozenset({"claude", "cursor", "codex", "gemini", "opencode"})
SESSION_PROVIDERS = RUN_PROVIDERS

RUN_STATUS_RUNNING = "running"
RUN_STATUS_QUEUED = "queued"
RUN_STATUS_PENDING = "pending"
RUN_STATUS_CANCELLING = "cancelling"
RUN_STATUS_COMPLETED = "completed"
RUN_STATUS_FAILED = "failed"
RUN_STATUS_CANCELLED = "cancelled"
RUN_STATUS_INTERRUPTED = "interrupted"

# These statuses still represent work that can be owned by a live background
# task. Keeping them centralized prevents pruning/restart recovery from drifting.
ACTIVE_RUN_STATUSES = frozenset(
    {
        RUN_STATUS_RUNNING,
        RUN_STATUS_QUEUED,
        RUN_STATUS_PENDING,
        RUN_STATUS_CANCELLING,
    }
)
TERMINAL_RUN_STATUSES = frozenset(
    {
        RUN_STATUS_COMPLETED,
        RUN_STATUS_FAILED,
        RUN_STATUS_CANCELLED,
        RUN_STATUS_INTERRUPTED,
    }
)
