from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    from .cloudcli_client import CloudCLIConfig
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli_client import CloudCLIConfig


@dataclass(frozen=True)
class ConnectorSettings:
    cloudcli: CloudCLIConfig
    auto_connect: bool
    recent_sessions_limit: int
    chat_messages_limit: int
    max_bindings_per_user: int
    max_run_message_length: int
    run_status_interval_seconds: int
    max_run_status_pushes: int
    run_list_limit: int
    agent_max_duration_seconds: int
    max_pending_display: int
    approval_allowed_user_keys: frozenset[str]
    approval_require_admin: bool
    approval_timeout_seconds: int
    approval_timeout_action: str
    max_push_text_length: int
    session_allowed_user_keys: frozenset[str]
    session_require_admin: bool
    allow_direct_session_id: bool
    run_allowed_user_keys: frozenset[str]
    run_require_admin: bool
    allowed_project_roots: tuple[str, ...]
    allow_unrestricted_project_paths: bool
    max_active_runs_per_user: int
    max_active_runs_global: int


def load_connector_settings(config: Any) -> ConnectorSettings:
    get = config.get if hasattr(config, "get") else lambda _key, default=None: default
    return ConnectorSettings(
        cloudcli=CloudCLIConfig(
            base_url=_read_base_url(get("cloudcli_base_url")),
            jwt_token=_read_str(get("cloudcli_jwt_token"), ""),
            username=_read_str(get("cloudcli_username"), ""),
            password=_read_str(get("cloudcli_password"), ""),
            api_key=_read_str(get("cloudcli_api_key"), ""),
            allow_unauthenticated_ws=_read_bool(get("allow_unauthenticated_ws"), False),
            timeout_seconds=_read_limited_int(get("request_timeout_seconds"), 8, 2, 120),
            agent_idle_timeout_seconds=_read_limited_int(
                get("agent_idle_timeout_seconds"),
                120,
                10,
                3600,
            ),
        ),
        auto_connect=_read_bool(get("auto_connect"), True),
        recent_sessions_limit=_read_limited_int(get("recent_sessions_limit"), 20, 1, 100),
        chat_messages_limit=_read_limited_int(get("chat_messages_limit"), 12, 1, 50),
        max_bindings_per_user=_read_limited_int(get("max_bindings_per_user"), 20, 1, 100),
        max_run_message_length=_read_limited_int(get("max_run_message_length"), 4000, 1, 20000),
        run_status_interval_seconds=_read_limited_int(get("run_status_interval_seconds"), 20, 1, 3600),
        max_run_status_pushes=_read_nonnegative_limited_int(get("max_run_status_pushes"), 10, 50),
        run_list_limit=_read_limited_int(get("run_list_limit"), 10, 1, 50),
        agent_max_duration_seconds=_read_nonnegative_limited_int(
            get("agent_max_duration_seconds"),
            7200,
            86400,
        ),
        max_pending_display=_read_limited_int(get("max_pending_display"), 30, 1, 100),
        approval_allowed_user_keys=frozenset(_read_str_list(get("approval_allowed_user_keys"))),
        approval_require_admin=_read_bool(get("approval_require_admin"), True),
        approval_timeout_seconds=_read_nonnegative_limited_int(get("approval_timeout_seconds"), 300, 86400),
        approval_timeout_action=_read_choice(get("approval_timeout_action"), "remind", {"remind", "deny"}),
        max_push_text_length=_read_limited_int(get("max_push_text_length"), 1800, 200, 8000),
        session_allowed_user_keys=frozenset(_read_str_list(get("session_allowed_user_keys"))),
        session_require_admin=_read_bool(get("session_require_admin"), True),
        allow_direct_session_id=_read_bool(get("allow_direct_session_id"), False),
        run_allowed_user_keys=frozenset(_read_str_list(get("run_allowed_user_keys"))),
        run_require_admin=_read_bool(get("run_require_admin"), True),
        allowed_project_roots=tuple(_read_str_list(get("allowed_project_roots"))),
        allow_unrestricted_project_paths=_read_bool(get("allow_unrestricted_project_paths"), False),
        max_active_runs_per_user=_read_nonnegative_limited_int(get("max_active_runs_per_user"), 1, 50),
        max_active_runs_global=_read_nonnegative_limited_int(get("max_active_runs_global"), 3, 200),
    )


def _read_str(value: Any, default: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else default


def _read_base_url(value: Any) -> str:
    raw = _read_str(value, "http://127.0.0.1:3001")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "http://127.0.0.1:3001"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "http://127.0.0.1:3001"
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return "http://127.0.0.1:3001"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _read_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _read_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _read_limited_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


def _read_nonnegative_limited_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < 0:
        return 0
    if parsed > maximum:
        return maximum
    return parsed


def _read_choice(value: Any, default: str, choices: set[str]) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in choices:
            return normalized
    return default
