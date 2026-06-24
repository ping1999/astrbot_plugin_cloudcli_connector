"""用户绑定和最近 session 序号缓存的仓库。"""

from __future__ import annotations

import time
from typing import Any

try:
    from ..core.sanitizer import safe_single_line_text
    from .state_models import UserRef, is_valid_session_id
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_single_line_text
    from persistence.state_models import UserRef, is_valid_session_id


MAX_SESSION_INDEX_ITEMS = 100


class UserStateRepository:
    """只操作状态字典中的 `users` 区域，不负责加锁和落盘。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def remember_user(self, user: UserRef) -> None:
        """记录用户最近出现的聊天 origin，供后续主动推送和迁移旧数据使用。"""
        entry = self.entry(user.user_key)
        entry["display_name"] = user.display_name
        origins = _read_list(entry.get("origins"))
        origin = origin_key(user)
        if origin not in origins:
            origins.append(origin)
        entry["origins"] = origins[-5:]
        entry["last_seen_at"] = time.time()

    def bind_session(self, user: UserRef, session_id: str, max_bindings: int) -> tuple[bool, str]:
        """把 session 绑定到当前聊天 origin；同一用户不同群/私聊互不干扰。"""
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        if max_bindings < 1:
            max_bindings = 1

        entry = self.entry(user.user_key)
        entry["display_name"] = user.display_name
        origins = _read_list(entry.get("origins"))
        origin = origin_key(user)
        if origin not in origins:
            origins.append(origin)
        entry["origins"] = origins[-5:]

        binding_origins = read_origin_map(entry.get("binding_origins"))
        session_origins = binding_origins.get(session_id, [])
        origin_added = False
        if origin not in session_origins:
            # 一个 session 可绑定到同一用户的多个聊天 origin，以便审批通知发回正确会话。
            session_origins.append(origin)
            binding_origins[session_id] = session_origins[-5:]
            entry["binding_origins"] = binding_origins
            origin_added = True

        bindings = _read_list(entry.get("bindings"))
        if session_id in bindings:
            if origin_added:
                return False, f"已绑定 session：{session_id}，并已为当前会话启用通知。"
            return False, f"已绑定 session：{session_id}"
        if len(bindings) >= max_bindings:
            return False, f"绑定数量已达上限 {max_bindings}。"
        bindings.append(session_id)
        entry["bindings"] = sorted(bindings)
        entry["binding_origins"] = binding_origins
        return True, f"已绑定 session：{session_id}"

    def unbind_session(self, user: UserRef, session_id: str) -> tuple[bool, str]:
        """只解除当前 origin 的绑定；其他 origin 仍可继续收到通知。"""
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        entry = self.entry(user.user_key)
        bindings = _read_list(entry.get("bindings"))
        binding_origins = read_origin_map(entry.get("binding_origins"))
        origins = binding_origins.get(session_id, [])
        origin = origin_key(user)
        if session_id not in bindings or origin not in origins:
            return False, f"未绑定 session：{session_id}"
        origins.remove(origin)
        if origins:
            binding_origins[session_id] = origins
        else:
            binding_origins.pop(session_id, None)
            bindings.remove(session_id)
        entry["bindings"] = sorted(bindings)
        entry["binding_origins"] = binding_origins
        return True, f"已解绑 session：{session_id}"

    def unbind_all(self, user: UserRef) -> tuple[bool, str]:
        """解除当前 origin 下的全部绑定。"""
        entry = self.entry(user.user_key)
        bindings = _read_list(entry.get("bindings"))
        binding_origins = read_origin_map(entry.get("binding_origins"))
        origin = origin_key(user)
        current = bindings_for_origin(entry, origin)
        count = len(current)
        for session_id in current:
            origins = binding_origins.get(session_id, [])
            if origin in origins:
                origins.remove(origin)
            if origins:
                binding_origins[session_id] = origins
            else:
                binding_origins.pop(session_id, None)
                if session_id in bindings:
                    bindings.remove(session_id)
        entry["bindings"] = sorted(bindings)
        entry["binding_origins"] = binding_origins
        if count == 0:
            return False, "当前没有绑定任何 session。"
        return True, f"已解绑全部 session，共 {count} 个。"

    def list_bindings(self, user: UserRef) -> list[str]:
        """列出当前 origin 下绑定的 session。"""
        return bindings_for_origin(self.entry(user.user_key), origin_key(user))

    def has_binding(self, user: UserRef, session_id: str) -> bool:
        """判断当前 origin 是否绑定了某个 session。"""
        if not is_valid_session_id(session_id):
            return False
        return session_id in bindings_for_origin(self.entry(user.user_key), origin_key(user))

    def remember_session_index(
        self,
        user: UserRef,
        sessions: list[dict[str, Any]],
        max_items: int = MAX_SESSION_INDEX_ITEMS,
    ) -> None:
        """缓存 `/cloudcli session` 展示出来的最近 session，供后续用序号引用。"""
        entry = self.entry(user.user_key)
        normalized = normalize_session_index_items(sessions, max_items)
        session_indexes = read_session_indexes(entry.get("session_indexes"))
        session_indexes[origin_key(user)] = {
            "items": normalized,
            "at": time.time(),
        }
        # 只保留最近几个 origin 的序号缓存，避免状态文件无限膨胀。
        known_origins = set(_read_list(entry.get("origins"))[-5:])
        entry["session_indexes"] = {
            origin: value
            for origin, value in session_indexes.items()
            if origin in known_origins or origin == origin_key(user)
        }

    def find_session_index_item(self, user: UserRef, session_id: str) -> dict[str, str] | None:
        """在当前 origin 的序号缓存中查找 session 元数据。"""
        if not is_valid_session_id(session_id):
            return None
        entry = self.entry(user.user_key)
        for item in session_index_for_origin(entry, origin_key(user)):
            if _read_str(item.get("id")) == session_id:
                return {
                    "id": session_id,
                    "provider": _read_str(item.get("provider")),
                    "projectName": _read_str(item.get("projectName")),
                    "projectPath": _read_str(item.get("projectPath")),
                }
        return None

    def resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        """把 `last`、数字序号或直接 sessionId 解析成统一字典。"""
        ref = ref.strip()
        if not ref:
            return None, "sessionId 不能为空。"
        if ref.lower() in {"last", "latest"}:
            index = 1
        elif ref.isdigit():
            index = int(ref)
        else:
            if not is_valid_session_id(ref):
                return None, "sessionId 格式不合法，只允许字母、数字、点、下划线、冒号和短横线。"
            return {"id": ref, "provider": ""}, None

        entry = self.entry(user.user_key)
        cached = session_index_for_origin(entry, origin_key(user))
        if not cached:
            return None, "没有可用的 session 序号缓存，请先执行 /cloudcli session。"
        if index < 1 or index > len(cached):
            return None, f"session 序号无效，请输入 1-{len(cached)}。"
        item = cached[index - 1]
        session_id = _read_str(item.get("id"))
        if not is_valid_session_id(session_id):
            return None, "缓存中的 sessionId 格式不合法，请重新执行 /cloudcli session。"
        return {
            "id": session_id,
            "provider": _read_str(item.get("provider")),
            "projectName": _read_str(item.get("projectName")),
            "projectPath": _read_str(item.get("projectPath")),
        }, None

    def users_bound_to_session(self, session_id: str) -> list[dict[str, Any]]:
        """查找绑定了某 session 的用户和 origin，用于审批主动通知。"""
        users = _read_dict(self.data.get("users"))
        result = []
        for user_key, entry in users.items():
            if not isinstance(entry, dict):
                continue
            if session_id in _read_list(entry.get("bindings")):
                binding_origins = read_origin_map(entry.get("binding_origins"))
                origins = binding_origins.get(session_id, [])
                if not origins:
                    continue
                result.append(
                    {
                        "user_key": user_key,
                        "display_name": _read_str(entry.get("display_name")),
                        "origins": origins,
                    }
                )
        return result

    def entry(self, user_key: str) -> dict[str, Any]:
        """读取或创建用户记录，并把旧版字段懒迁移到按 origin 分组的新结构。"""
        users = _read_dict(self.data.get("users"))
        self.data["users"] = users
        entry = users.setdefault(user_key, _empty_user_entry())
        if not isinstance(entry, dict):
            entry = _empty_user_entry()
            users[user_key] = entry
        if "binding_origins" not in entry:
            # 旧版本只有 bindings/origins；如果只有一个 origin，可以安全迁移为按 origin 绑定。
            origins = _read_list(entry.get("origins"))
            bindings = _read_list(entry.get("bindings"))
            if len(origins) == 1 and bindings:
                entry["binding_origins"] = {
                    session_id: origins[:]
                    for session_id in bindings
                    if is_valid_session_id(session_id)
                }
            else:
                entry["binding_origins"] = {}
        if "session_indexes" not in entry:
            # 同样把旧版单份 session_index 迁移到当前唯一 origin 下。
            origins = _read_list(entry.get("origins"))
            legacy_items = _read_dict_list(entry.get("session_index"))
            if len(origins) == 1 and legacy_items:
                entry["session_indexes"] = {
                    origins[0]: {
                        "items": legacy_items,
                        "at": _parse_timestamp(entry.get("session_index_at")),
                    }
                }
            else:
                entry["session_indexes"] = {}
        return entry


def origin_key(user: UserRef | None) -> str:
    """返回当前聊天会话作用域；没有用户时用于系统记录。"""
    if user is None:
        return ""
    return user.unified_msg_origin or "__default__"


def bindings_for_origin(entry: dict[str, Any], origin: str) -> list[str]:
    """从用户记录中提取某个 origin 下可见的 session 绑定。"""
    binding_origins = read_origin_map(entry.get("binding_origins"))
    return sorted(
        session_id
        for session_id, origins in binding_origins.items()
        if origin in origins
    )


def read_origin_map(value: Any) -> dict[str, list[str]]:
    """读取 `{session_id: [origin...]}` 结构，并过滤非法 sessionId。"""
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, raw_origins in value.items():
        session_id = _read_str(key)
        if not is_valid_session_id(session_id):
            continue
        origins = _read_list(raw_origins)
        if origins:
            result[session_id] = origins[-5:]
    return result


def read_session_indexes(value: Any) -> dict[str, dict[str, Any]]:
    """读取按 origin 分组的 session 序号缓存。"""
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for origin, raw in value.items():
        if not isinstance(origin, str) or not isinstance(raw, dict):
            continue
        result[origin] = {
            "items": _read_dict_list(raw.get("items")),
            "at": _parse_timestamp(raw.get("at")),
        }
    return result


def session_index_for_origin(entry: dict[str, Any], origin: str) -> list[dict[str, Any]]:
    """获取当前 origin 下的最近 session 缓存列表。"""
    scoped = read_session_indexes(entry.get("session_indexes")).get(origin)
    if isinstance(scoped, dict):
        return _read_dict_list(scoped.get("items"))
    return []


def normalize_session_index_items(
    sessions: list[dict[str, Any]],
    max_items: int = MAX_SESSION_INDEX_ITEMS,
) -> list[dict[str, str]]:
    """Normalize recent session metadata before storing or caching it.

    The same helper is used by disk-backed state and in-memory state so index
    references resolve consistently, while display-oriented text is single-line.
    """
    seen: set[str] = set()
    normalized: list[dict[str, str]] = []
    for item in sessions:
        if not isinstance(item, dict):
            continue
        session_id = _read_str(
            item.get("id") or item.get("sessionId") or item.get("session_id")
        ).strip()
        if not is_valid_session_id(session_id) or session_id in seen:
            continue
        seen.add(session_id)
        normalized.append(
            {
                "id": session_id,
                "provider": safe_single_line_text(item.get("provider"), 60),
                "projectName": safe_single_line_text(item.get("projectName"), 160),
                "projectPath": safe_single_line_text(item.get("projectPath"), 500),
                "summary": safe_single_line_text(item.get("summary"), 240),
                "lastActivity": safe_single_line_text(item.get("lastActivity"), 80),
            }
        )
        if len(normalized) >= max(1, min(max_items, MAX_SESSION_INDEX_ITEMS)):
            break
    return normalized


def _empty_user_entry() -> dict[str, Any]:
    """创建新用户记录的默认结构。"""
    return {
        "display_name": "",
        "origins": [],
        "bindings": [],
        "binding_origins": {},
        "last_seen_at": 0,
        "session_index": [],
        "session_index_at": 0,
        "session_indexes": {},
    }


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _read_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            from datetime import datetime

            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0
    return 0
