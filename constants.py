from __future__ import annotations


PLUGIN_NAME = "astrbot_plugin_cloudcli_connector"
MAX_DENY_REASON_LEN = 500
RUN_PROVIDERS = frozenset({"claude", "cursor", "codex", "gemini"})
SESSION_PROVIDERS = RUN_PROVIDERS | frozenset({"opencode"})
