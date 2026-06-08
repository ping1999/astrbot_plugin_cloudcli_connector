from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")


@dataclass(frozen=True)
class UserRef:
    user_key: str
    display_name: str
    unified_msg_origin: str


@dataclass
class PendingApproval:
    request_id: str
    session_id: str
    tool_name: str
    input_data: Any
    provider: str = "claude"
    received_at: float = 0

    @classmethod
    def from_cloudcli(cls, payload: dict[str, Any]) -> "PendingApproval | None":
        request_id = _read_str(payload.get("requestId") or payload.get("request_id"))
        session_id = _read_str(payload.get("sessionId") or payload.get("session_id"))
        if not request_id or not session_id:
            return None
        if not REQUEST_ID_RE.fullmatch(request_id) or not SESSION_ID_RE.fullmatch(session_id):
            return None
        return cls(
            request_id=request_id,
            session_id=session_id,
            tool_name=_read_str(payload.get("toolName") or payload.get("tool_name")) or "UnknownTool",
            input_data=payload.get("input"),
            provider=_read_str(payload.get("provider")) or "claude",
            received_at=_parse_timestamp(payload.get("receivedAt")) or time.time(),
        )


class PluginState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._data: dict[str, Any] = {
            "version": 1,
            "users": {},
            "pending": {},
        }

    async def load(self) -> None:
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                await self._save_locked()
                return
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data["users"] = _read_dict(loaded.get("users"))
                    self._data["pending"] = _read_dict(loaded.get("pending"))
            except (OSError, json.JSONDecodeError):
                backup = self.path.with_suffix(f".bad-{int(time.time())}.json")
                try:
                    self.path.replace(backup)
                except OSError:
                    pass
                self._data = {"version": 1, "users": {}, "pending": {}}
                await self._save_locked()

    async def remember_user(self, user: UserRef) -> None:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            entry["display_name"] = user.display_name
            origins = _read_list(entry.get("origins"))
            if user.unified_msg_origin not in origins:
                origins.append(user.unified_msg_origin)
            entry["origins"] = origins[-5:]
            entry["last_seen_at"] = time.time()
            await self._save_locked()

    async def bind_session(
        self,
        user: UserRef,
        session_id: str,
        max_bindings: int,
    ) -> tuple[bool, str]:
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        if max_bindings < 1:
            max_bindings = 1
        async with self._lock:
            entry = self._user_entry(user.user_key)
            entry["display_name"] = user.display_name
            origins = _read_list(entry.get("origins"))
            if user.unified_msg_origin not in origins:
                origins.append(user.unified_msg_origin)
            entry["origins"] = origins[-5:]
            bindings = _read_list(entry.get("bindings"))
            if session_id in bindings:
                return False, f"已绑定 session：{session_id}"
            if len(bindings) >= max_bindings:
                return False, f"绑定数量已达上限 {max_bindings}。"
            bindings.append(session_id)
            entry["bindings"] = sorted(bindings)
            await self._save_locked()
            return True, f"已绑定 session：{session_id}"

    async def unbind_session(self, user: UserRef, session_id: str) -> tuple[bool, str]:
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        async with self._lock:
            entry = self._user_entry(user.user_key)
            bindings = _read_list(entry.get("bindings"))
            if session_id not in bindings:
                return False, f"未绑定 session：{session_id}"
            bindings.remove(session_id)
            entry["bindings"] = sorted(bindings)
            await self._save_locked()
            return True, f"已解绑 session：{session_id}"

    async def unbind_all(self, user: UserRef) -> tuple[bool, str]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            count = len(_read_list(entry.get("bindings")))
            entry["bindings"] = []
            await self._save_locked()
            if count == 0:
                return False, "当前没有绑定任何 session。"
            return True, f"已解绑全部 session，共 {count} 个。"

    async def list_bindings(self, user: UserRef) -> list[str]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            return sorted(_read_list(entry.get("bindings")))

    async def users_bound_to_session(self, session_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            users = _read_dict(self._data.get("users"))
            result = []
            for user_key, entry in users.items():
                if not isinstance(entry, dict):
                    continue
                if session_id in _read_list(entry.get("bindings")):
                    result.append(
                        {
                            "user_key": user_key,
                            "display_name": _read_str(entry.get("display_name")),
                            "origins": _read_list(entry.get("origins")),
                        }
                    )
            return result

    async def upsert_pending(self, approval: PendingApproval) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            pending[approval.request_id] = {
                "request_id": approval.request_id,
                "session_id": approval.session_id,
                "tool_name": approval.tool_name,
                "input_data": approval.input_data,
                "provider": approval.provider,
                "received_at": approval.received_at or time.time(),
                "resolved": False,
            }
            self._data["pending"] = pending
            await self._save_locked()

    async def remove_pending(self, request_id: str) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            pending.pop(request_id, None)
            self._data["pending"] = pending
            await self._save_locked()

    async def merge_pending(self, approvals: list[PendingApproval]) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            for approval in approvals:
                pending[approval.request_id] = {
                    "request_id": approval.request_id,
                    "session_id": approval.session_id,
                    "tool_name": approval.tool_name,
                    "input_data": approval.input_data,
                    "provider": approval.provider,
                    "received_at": approval.received_at or time.time(),
                    "resolved": False,
                }
            self._data["pending"] = pending
            await self._save_locked()

    async def visible_pending_for_user(
        self,
        user: UserRef,
        max_items: int,
    ) -> list[PendingApproval]:
        async with self._lock:
            bindings = _read_list(self._user_entry(user.user_key).get("bindings"))
            if not bindings:
                return []
            pending = _read_dict(self._data.get("pending"))
            approvals = []
            for item in pending.values():
                if not isinstance(item, dict):
                    continue
                session_id = _read_str(item.get("session_id"))
                request_id = _read_str(item.get("request_id"))
                if session_id not in bindings or not request_id:
                    continue
                if item.get("resolved") is True:
                    continue
                approvals.append(
                    PendingApproval(
                        request_id=request_id,
                        session_id=session_id,
                        tool_name=_read_str(item.get("tool_name")) or "UnknownTool",
                        input_data=item.get("input_data"),
                        provider=_read_str(item.get("provider")) or "claude",
                        received_at=float(item.get("received_at") or 0),
                    )
                )
            approvals.sort(key=lambda item: (item.received_at, item.request_id))
            if max_items < 1:
                max_items = 1
            return approvals[:max_items]

    async def resolve_visible_request(
        self,
        user: UserRef,
        request_no: int | None,
        max_items: int,
    ) -> tuple[PendingApproval | None, str | None]:
        visible = await self.visible_pending_for_user(user, max_items)
        if not visible:
            return None, "当前没有待审批权限。"
        if request_no is None:
            if len(visible) != 1:
                return None, "有多条待审批权限，请指定序号。"
            return visible[0], None
        if request_no < 1 or request_no > len(visible):
            return None, f"序号无效，请输入 1-{len(visible)}。"
        return visible[request_no - 1], None

    def _user_entry(self, user_key: str) -> dict[str, Any]:
        users = _read_dict(self._data.get("users"))
        self._data["users"] = users
        entry = users.setdefault(
            user_key,
            {"display_name": "", "origins": [], "bindings": [], "last_seen_at": 0},
        )
        if not isinstance(entry, dict):
            entry = {"display_name": "", "origins": [], "bindings": [], "last_seen_at": 0}
            users[user_key] = entry
        return entry

    async def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp_path, self.path)


def is_valid_session_id(value: str) -> bool:
    return bool(SESSION_ID_RE.fullmatch(value or ""))


def is_valid_request_id(value: str) -> bool:
    return bool(REQUEST_ID_RE.fullmatch(value or ""))


def resolve_data_path(plugin_file: str, plugin_name: str) -> Path:
    env_path = os.getenv("ASTRBOT_DATA_PATH") or os.getenv("ASTRBOT_DATA_DIR")
    if env_path:
        return Path(env_path) / "plugins" / plugin_name

    plugin_dir = Path(plugin_file).resolve().parent
    for parent in plugin_dir.parents:
        if parent.name == "data" and (parent / "plugins").exists():
            return parent / "plugin_data" / plugin_name

    return plugin_dir / ".runtime_data"


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


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
