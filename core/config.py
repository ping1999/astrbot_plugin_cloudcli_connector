"""插件配置读取和安全归一化。"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    from ..cloudcli.cloudcli_client import CloudCLIConfig
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_client import CloudCLIConfig


@dataclass(frozen=True)
class ConnectorSettings:
    """插件运行期使用的不可变配置快照。"""

    cloudcli: CloudCLIConfig
    auto_connect: bool
    recent_sessions_limit: int
    session_index_ttl_seconds: int
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
    approval_access_mode: str
    approval_push_details_to_authenticated: bool
    approval_allow_direct_session_bind: bool
    approval_timeout_seconds: int
    approval_timeout_action: str
    max_push_text_length: int
    session_allowed_user_keys: frozenset[str]
    session_require_admin: bool
    session_access_mode: str
    stop_allowed_user_keys: frozenset[str]
    stop_require_admin: bool
    stop_access_mode: str
    allow_direct_session_id: bool
    run_allowed_user_keys: frozenset[str]
    run_require_admin: bool
    run_access_mode: str
    allowed_project_roots: tuple[str, ...]
    allow_unrestricted_project_paths: bool
    max_active_runs_per_user: int
    max_active_runs_global: int
    max_run_history_per_user: int
    max_run_history_global: int
    persist_sensitive_state: bool


def load_connector_settings(config: Any) -> ConnectorSettings:
    """从 AstrBot 配置对象中读取所有选项，并为缺失/非法值套用安全默认值。"""
    get = config.get if hasattr(config, "get") else lambda _key, default=None: default
    jwt_token = _read_str(get("cloudcli_jwt_token"), "")
    username = _read_str(get("cloudcli_username"), "")
    password = _read_str(get("cloudcli_password"), "")
    api_key = _read_str(get("cloudcli_api_key"), "")
    approval_require_admin = _read_bool(get("approval_require_admin"), True)
    session_require_admin = _read_bool(get("session_require_admin"), True)
    stop_require_admin = _read_bool(get("stop_require_admin"), True)
    run_require_admin = _read_bool(get("run_require_admin"), True)
    has_cloudcli_credentials = bool(jwt_token or api_key or (username and password))
    # 所有数字配置都在读取时夹到合理范围内，避免错误配置导致无限等待或消息过长。
    return ConnectorSettings(
        cloudcli=CloudCLIConfig(
            base_url=_read_base_url(
                get("cloudcli_base_url"),
                has_credentials=has_cloudcli_credentials,
            ),
            jwt_token=jwt_token,
            username=username,
            password=password,
            api_key=api_key,
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
        session_index_ttl_seconds=_read_limited_int(
            get("session_index_ttl_seconds"),
            3600,
            60,
            86400,
        ),
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
        approval_require_admin=approval_require_admin,
        approval_access_mode=_read_access_mode(
            get("approval_access_mode"),
            legacy_require_admin=approval_require_admin,
        ),
        approval_push_details_to_authenticated=_read_bool(
            get("approval_push_details_to_authenticated"),
            False,
        ),
        approval_allow_direct_session_bind=_read_bool(get("approval_allow_direct_session_bind"), False),
        approval_timeout_seconds=_read_nonnegative_limited_int(get("approval_timeout_seconds"), 300, 86400),
        approval_timeout_action=_read_choice(get("approval_timeout_action"), "remind", {"remind", "deny"}),
        max_push_text_length=_read_limited_int(get("max_push_text_length"), 1800, 200, 8000),
        session_allowed_user_keys=frozenset(_read_str_list(get("session_allowed_user_keys"))),
        session_require_admin=session_require_admin,
        session_access_mode=_read_access_mode(
            get("session_access_mode"),
            legacy_require_admin=session_require_admin,
        ),
        stop_allowed_user_keys=frozenset(_read_str_list(get("stop_allowed_user_keys"))),
        stop_require_admin=stop_require_admin,
        stop_access_mode=_read_access_mode(
            get("stop_access_mode"),
            legacy_require_admin=stop_require_admin,
        ),
        allow_direct_session_id=_read_bool(get("allow_direct_session_id"), False),
        run_allowed_user_keys=frozenset(_read_str_list(get("run_allowed_user_keys"))),
        run_require_admin=run_require_admin,
        run_access_mode=_read_access_mode(
            get("run_access_mode"),
            legacy_require_admin=run_require_admin,
        ),
        allowed_project_roots=tuple(_read_str_list(get("allowed_project_roots"))),
        allow_unrestricted_project_paths=_read_bool(get("allow_unrestricted_project_paths"), False),
        max_active_runs_per_user=_read_nonnegative_limited_int(get("max_active_runs_per_user"), 1, 50),
        max_active_runs_global=_read_nonnegative_limited_int(get("max_active_runs_global"), 3, 200),
        max_run_history_per_user=_read_nonnegative_limited_int(get("max_run_history_per_user"), 50, 1000),
        max_run_history_global=_read_nonnegative_limited_int(get("max_run_history_global"), 500, 10000),
        persist_sensitive_state=_read_bool(get("persist_sensitive_state"), False),
    )


def _read_str(value: Any, default: str) -> str:
    """读取非空字符串，否则返回默认值。"""
    return value.strip() if isinstance(value, str) and value.strip() else default


def _read_base_url(value: Any, *, has_credentials: bool = False) -> str:
    """校验 CloudCLI base URL；携带凭据时禁止非本机 HTTP 明文地址。"""
    raw = _read_str(value, "http://127.0.0.1:3001")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "http://127.0.0.1:3001"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "http://127.0.0.1:3001"
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return "http://127.0.0.1:3001"
    try:
        safe_netloc = _base_url_netloc(parsed)
    except ValueError:
        return "http://127.0.0.1:3001"
    if not safe_netloc:
        return "http://127.0.0.1:3001"
    if (
        has_credentials
        and parsed.scheme == "http"
        and not _is_loopback_hostname(parsed.hostname or "")
    ):
        # 避免把 JWT、密码或 API key 通过明文 HTTP 发到远端主机。
        return "http://127.0.0.1:3001"
    return urlunsplit((parsed.scheme, safe_netloc, parsed.path.rstrip("/"), "", ""))


def _base_url_netloc(parsed: Any) -> str:
    """重建 netloc，顺手移除 URL 中误填的用户名密码。"""
    if parsed.username or parsed.password:
        hostname = parsed.hostname or ""
        if not hostname:
            return ""
        host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        return f"{host}:{parsed.port}" if parsed.port is not None else host
    if parsed.port is not None:
        return parsed.netloc
    return parsed.netloc


def _is_loopback_hostname(hostname: str) -> bool:
    """判断主机名是否是 localhost 或回环 IP。"""
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _read_bool(value: Any, default: bool) -> bool:
    """只接受真实 bool，避免字符串 'false' 被 Python 当作 True。"""
    return value if isinstance(value, bool) else default


def _read_str_list(value: Any) -> list[str]:
    """读取字符串列表；也兼容逗号分隔的配置写法。"""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _read_limited_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    """读取整数并限制在闭区间 `[minimum, maximum]` 内。"""
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
    """读取非负整数；0 通常表示关闭某类限制或超时。"""
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
    """读取枚举值，大小写不敏感。"""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in choices:
            return normalized
    return default


def _read_access_mode(value: Any, *, legacy_require_admin: bool) -> str:
    """读取访问模式，并兼容早期 `*_require_admin` 布尔配置。"""
    choices = {"admin_or_allowlist", "allowlist_only", "authenticated"}
    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_")
        aliases = {
            "admin": "admin_or_allowlist",
            "admin_only": "admin_or_allowlist",
            "allowlist": "allowlist_only",
            "allowlisted": "allowlist_only",
            "authenticated_users": "authenticated",
            "all_authenticated": "authenticated",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized in choices:
            return normalized
    return "admin_or_allowlist" if legacy_require_admin else "allowlist_only"
