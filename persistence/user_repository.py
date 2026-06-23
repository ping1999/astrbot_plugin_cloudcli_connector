from __future__ import annotations

import time
from typing import Any

try:
    from ..core.sanitizer import safe_text
    from .state_models import UserRef, is_valid_session_id
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_text
    from persistence.state_models import UserRef, is_valid_session_id


MAX_SESSION_INDEX_ITEMS = 100


class UserStateRepository:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def remember_user(self, user: UserRef) -> None:
        entry = self.entry(user.user_key)
        entry["display_name"] = user.display_name
        origins = _read_list(entry.get("origins"))
        origin = origin_key(user)
        if origin not in origins:
            origins.append(origin)
        entry["origins"] = origins[-5:]
        entry["last_seen_at"] = time.time()

    def bind_session(self, user: UserRef, session_id: str, max_bindings: int) -> tuple[bool, str]:
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
        return bindings_for_origin(self.entry(user.user_key), origin_key(user))

    def has_binding(self, user: UserRef, session_id: str) -> bool:
        if not is_valid_session_id(session_id):
            return False
        return session_id in bindings_for_origin(self.entry(user.user_key), origin_key(user))

    def remember_session_index(
        self,
        user: UserRef,
        sessions: list[dict[str, Any]],
        max_items: int = MAX_SESSION_INDEX_ITEMS,
    ) -> None:
        entry = self.entry(user.user_key)
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
                    "provider": safe_text(item.get("provider"), 60),
                    "projectName": safe_text(item.get("projectName"), 160),
                    "projectPath": safe_text(item.get("projectPath"), 500),
                    "summary": safe_text(item.get("summary"), 240),
                    "lastActivity": safe_text(item.get("lastActivity"), 80),
                }
            )
            if len(normalized) >= max(1, min(max_items, MAX_SESSION_INDEX_ITEMS)):
                break
        session_indexes = read_session_indexes(entry.get("session_indexes"))
        session_indexes[origin_key(user)] = {
            "items": normalized,
            "at": time.time(),
        }
        known_origins = set(_read_list(entry.get("origins"))[-5:])
        entry["session_indexes"] = {
            origin: value
            for origin, value in session_indexes.items()
            if origin in known_origins or origin == origin_key(user)
        }

    def find_session_index_item(self, user: UserRef, session_id: str) -> dict[str, str] | None:
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
        users = _read_dict(self.data.get("users"))
        self.data["users"] = users
        entry = users.setdefault(user_key, _empty_user_entry())
        if not isinstance(entry, dict):
            entry = _empty_user_entry()
            users[user_key] = entry
        if "binding_origins" not in entry:
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
    if user is None:
        return ""
    return user.unified_msg_origin or "__default__"


def bindings_for_origin(entry: dict[str, Any], origin: str) -> list[str]:
    binding_origins = read_origin_map(entry.get("binding_origins"))
    return sorted(
        session_id
        for session_id, origins in binding_origins.items()
        if origin in origins
    )


def read_origin_map(value: Any) -> dict[str, list[str]]:
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
    scoped = read_session_indexes(entry.get("session_indexes")).get(origin)
    if isinstance(scoped, dict):
        return _read_dict_list(scoped.get("items"))
    return []


def _empty_user_entry() -> dict[str, Any]:
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
