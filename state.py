from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

try:
    from .sanitizer import compact_json, safe_json_value, safe_text
    from .state_models import (
        PendingApproval,
        UserRef,
        is_valid_request_id,
        is_valid_session_id,
        pending_storage_key,
        safe_inline_text,
    )
    from .state_storage import JsonStateStore
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from sanitizer import compact_json, safe_json_value, safe_text
    from state_models import (
        PendingApproval,
        UserRef,
        is_valid_request_id,
        is_valid_session_id,
        pending_storage_key,
        safe_inline_text,
    )
    from state_storage import JsonStateStore

RUN_ID_RE = re.compile(r"^[0-9]{1,12}$")

MAX_SESSION_INDEX_ITEMS = 100
MAX_RUN_LOG_ITEMS = 80
MAX_AUDIT_ITEMS = 500
DEFAULT_MAX_RUN_HISTORY_PER_USER = 50
DEFAULT_MAX_RUN_HISTORY_GLOBAL = 500
MAX_STORED_TEXT = 1200
PENDING_CLAIM_FIELDS = ("claimed_by", "claimed_action", "claimed_at")


class PluginState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.store = JsonStateStore(path)
        self._lock = asyncio.Lock()
        self._data: dict[str, Any] = {
            "version": 3,
            "users": {},
            "pending": {},
            "runs": {},
            "audit": [],
            "next_run_id": 1,
        }

    async def load(self) -> None:
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                await self._save_locked()
                return
            try:
                loaded = self.store.read()
                if isinstance(loaded, dict):
                    self._data["version"] = 3
                    self._data["users"] = _read_dict(loaded.get("users"))
                    self._data["pending"] = _normalize_pending_records(_read_dict(loaded.get("pending")))
                    self._data["runs"] = _normalize_run_records(_read_dict(loaded.get("runs")))
                    self._data["audit"] = _normalize_audit_records(loaded.get("audit"))[-MAX_AUDIT_ITEMS:]
                    self._data["next_run_id"] = _read_positive_int(
                        loaded.get("next_run_id"),
                        self._guess_next_run_id(self._data["runs"]),
                    )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                self.store.backup_bad_file()
                self._data = {
                    "version": 3,
                    "users": {},
                    "pending": {},
                    "runs": {},
                    "audit": [],
                    "next_run_id": 1,
                }
                await self._save_locked()

    async def remember_user(self, user: UserRef) -> None:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            entry["display_name"] = user.display_name
            origins = _read_list(entry.get("origins"))
            origin = _origin_key(user)
            if origin not in origins:
                origins.append(origin)
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
            origin = _origin_key(user)
            if origin not in origins:
                origins.append(origin)
            entry["origins"] = origins[-5:]
            binding_origins = _read_origin_map(entry.get("binding_origins"))
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
                    await self._save_locked()
                    return False, f"已绑定 session：{session_id}，并已为当前会话启用通知。"
                return False, f"已绑定 session：{session_id}"
            if len(bindings) >= max_bindings:
                return False, f"绑定数量已达上限 {max_bindings}。"
            bindings.append(session_id)
            entry["bindings"] = sorted(bindings)
            entry["binding_origins"] = binding_origins
            await self._save_locked()
            return True, f"已绑定 session：{session_id}"

    async def unbind_session(self, user: UserRef, session_id: str) -> tuple[bool, str]:
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        async with self._lock:
            entry = self._user_entry(user.user_key)
            bindings = _read_list(entry.get("bindings"))
            binding_origins = _read_origin_map(entry.get("binding_origins"))
            origins = binding_origins.get(session_id, [])
            origin = _origin_key(user)
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
            await self._save_locked()
            return True, f"已解绑 session：{session_id}"

    async def unbind_all(self, user: UserRef) -> tuple[bool, str]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            bindings = _read_list(entry.get("bindings"))
            binding_origins = _read_origin_map(entry.get("binding_origins"))
            origin = _origin_key(user)
            current = _bindings_for_origin(entry, origin)
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
            await self._save_locked()
            if count == 0:
                return False, "当前没有绑定任何 session。"
            return True, f"已解绑全部 session，共 {count} 个。"

    async def list_bindings(self, user: UserRef) -> list[str]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            return _bindings_for_origin(entry, _origin_key(user))

    async def has_binding(self, user: UserRef, session_id: str) -> bool:
        if not is_valid_session_id(session_id):
            return False
        async with self._lock:
            entry = self._user_entry(user.user_key)
            return session_id in _bindings_for_origin(entry, _origin_key(user))

    async def remember_session_index(
        self,
        user: UserRef,
        sessions: list[dict[str, Any]],
        max_items: int = MAX_SESSION_INDEX_ITEMS,
    ) -> None:
        async with self._lock:
            entry = self._user_entry(user.user_key)
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
            session_indexes = _read_session_indexes(entry.get("session_indexes"))
            session_indexes[_origin_key(user)] = {
                "items": normalized,
                "at": time.time(),
            }
            known_origins = set(_read_list(entry.get("origins"))[-5:])
            entry["session_indexes"] = {
                origin: value
                for origin, value in session_indexes.items()
                if origin in known_origins or origin == _origin_key(user)
            }
            await self._save_locked()

    async def find_session_index_item(self, user: UserRef, session_id: str) -> dict[str, str] | None:
        if not is_valid_session_id(session_id):
            return None
        async with self._lock:
            entry = self._user_entry(user.user_key)
            for item in _session_index_for_origin(entry, _origin_key(user)):
                if _read_str(item.get("id")) == session_id:
                    return {
                        "id": session_id,
                        "provider": _read_str(item.get("provider")),
                        "projectName": _read_str(item.get("projectName")),
                        "projectPath": _read_str(item.get("projectPath")),
                    }
        return None

    async def resolve_session_ref(
        self,
        user: UserRef,
        ref: str,
    ) -> tuple[dict[str, str] | None, str | None]:
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

        async with self._lock:
            entry = self._user_entry(user.user_key)
            cached = _session_index_for_origin(entry, _origin_key(user))
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

    async def users_bound_to_session(self, session_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            users = _read_dict(self._data.get("users"))
            result = []
            for user_key, entry in users.items():
                if not isinstance(entry, dict):
                    continue
                if session_id in _read_list(entry.get("bindings")):
                    binding_origins = _read_origin_map(entry.get("binding_origins"))
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

    async def upsert_pending(self, approval: PendingApproval) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            key = pending_storage_key(approval.session_id, approval.request_id)
            if not key:
                return
            pending[key] = self._pending_record(approval, pending.get(key))
            self._data["pending"] = pending
            await self._save_locked()

    async def remove_pending(self, session_id: str, request_id: str) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            pending.pop(pending_storage_key(session_id, request_id), None)
            self._data["pending"] = pending
            await self._save_locked()

    async def get_pending(self, session_id: str, request_id: str) -> PendingApproval | None:
        async with self._lock:
            item = _read_dict(self._data.get("pending")).get(
                pending_storage_key(session_id, request_id)
            )
            if not isinstance(item, dict) or item.get("resolved") is True:
                return None
            session_id = _read_str(item.get("session_id"))
            if not is_valid_session_id(session_id):
                return None
            return PendingApproval(
                request_id=_read_str(item.get("request_id")) or request_id,
                session_id=session_id,
                tool_name=_read_str(item.get("tool_name")) or "UnknownTool",
                input_data=item.get("input_data"),
                provider=_read_str(item.get("provider")) or "claude",
                received_at=float(item.get("received_at") or 0),
            )

    async def list_pending(self) -> list[PendingApproval]:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            approvals: list[PendingApproval] = []
            for item in pending.values():
                approval = self._pending_from_record(item)
                if approval is not None:
                    approvals.append(approval)
            approvals.sort(key=lambda item: (item.received_at, item.session_id, item.request_id))
            return approvals

    async def merge_pending(self, approvals: list[PendingApproval]) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            for approval in approvals:
                key = pending_storage_key(approval.session_id, approval.request_id)
                if key:
                    pending[key] = self._pending_record(approval, pending.get(key))
            self._data["pending"] = pending
            await self._save_locked()

    async def replace_pending_for_session(
        self,
        session_id: str,
        approvals: list[PendingApproval],
    ) -> list[str]:
        if not is_valid_session_id(session_id):
            return []
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            incoming = {
                pending_storage_key(approval.session_id, approval.request_id): approval
                for approval in approvals
                if approval.session_id == session_id and is_valid_request_id(approval.request_id)
            }
            removed: list[str] = []
            for key, item in list(pending.items()):
                if not isinstance(item, dict):
                    continue
                if _read_str(item.get("session_id")) == session_id and key not in incoming:
                    removed.append(key)
                    pending.pop(key, None)
            for key, approval in incoming.items():
                if key:
                    pending[key] = self._pending_record(approval, pending.get(key))
            self._data["pending"] = pending
            await self._save_locked()
            return removed

    async def visible_pending_for_user(
        self,
        user: UserRef,
        max_items: int,
    ) -> list[PendingApproval]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            bindings = _bindings_for_origin(entry, _origin_key(user))
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

    async def claim_visible_request(
        self,
        user: UserRef,
        request_no: int | None,
        max_items: int,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            bindings = _bindings_for_origin(entry, _origin_key(user))
            visible = self._visible_pending_locked(bindings, max_items)
            if not visible:
                return None, "当前没有待审批权限。"
            if request_no is None:
                if len(visible) != 1:
                    return None, "有多条待审批权限，请指定序号。"
                approval = visible[0]
            else:
                if request_no < 1 or request_no > len(visible):
                    return None, f"序号无效，请输入 1-{len(visible)}。"
                approval = visible[request_no - 1]
            return await self._claim_pending_locked(
                approval.session_id,
                approval.request_id,
                actor=user.user_key,
                action=action,
            )

    async def claim_pending(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        async with self._lock:
            return await self._claim_pending_locked(
                session_id,
                request_id,
                actor=actor,
                action=action,
            )

    async def release_pending_claim(self, session_id: str, request_id: str, actor: str) -> None:
        async with self._lock:
            pending = _read_dict(self._data.get("pending"))
            key = pending_storage_key(session_id, request_id)
            item = pending.get(key)
            if not isinstance(item, dict):
                return
            if _read_str(item.get("claimed_by")) != actor:
                return
            for field in PENDING_CLAIM_FIELDS:
                item.pop(field, None)
            pending[key] = item
            self._data["pending"] = pending
            await self._save_locked()

    async def create_run_task(
        self,
        user: UserRef,
        payload: dict[str, Any],
        display_target: str,
        max_history_per_user: int = DEFAULT_MAX_RUN_HISTORY_PER_USER,
        max_history_global: int = DEFAULT_MAX_RUN_HISTORY_GLOBAL,
    ) -> str:
        async with self._lock:
            run_id = str(_read_positive_int(self._data.get("next_run_id"), 1))
            self._data["next_run_id"] = int(run_id) + 1
            runs = _read_dict(self._data.get("runs"))
            now = time.time()
            runs[run_id] = {
                "id": run_id,
                "user_key": user.user_key,
                "display_name": user.display_name,
                "origin": _origin_key(user),
                "status": "running",
                "provider": safe_text(payload.get("provider"), 60) or "claude",
                "session_id": safe_text(payload.get("sessionId"), 200),
                "project_path": safe_text(payload.get("projectPath"), 500),
                "github_url": safe_text(payload.get("githubUrl"), 500),
                "target": safe_text(display_target, 500),
                "message": safe_text(payload.get("message"), MAX_STORED_TEXT),
                "started_at": now,
                "updated_at": now,
                "finished_at": 0,
                "log": [],
                "summary": {},
            }
            self._prune_runs_locked(runs, max_history_per_user, max_history_global)
            self._data["runs"] = runs
            await self._save_locked()
            return run_id

    async def update_run_task(
        self,
        run_id: str,
        *,
        status: str | None = None,
        event: str | None = None,
        session_id: str | None = None,
        summary: dict[str, Any] | None = None,
        error: str | None = None,
        finished: bool = False,
    ) -> None:
        if not RUN_ID_RE.fullmatch(run_id):
            return
        async with self._lock:
            runs = _read_dict(self._data.get("runs"))
            item = runs.get(run_id)
            if not isinstance(item, dict):
                return
            now = time.time()
            if status:
                item["status"] = safe_text(status, 40)
            if session_id and is_valid_session_id(session_id):
                item["session_id"] = session_id
            if summary is not None:
                item["summary"] = safe_json_value(summary)
            if error:
                item["error"] = safe_text(error, MAX_STORED_TEXT)
            if event:
                log = _read_dict_list(item.get("log"))
                log.append({"ts": now, "text": safe_text(event, MAX_STORED_TEXT)})
                item["log"] = log[-MAX_RUN_LOG_ITEMS:]
            if finished:
                item["finished_at"] = now
            item["updated_at"] = now
            runs[run_id] = item
            self._data["runs"] = runs
            await self._save_locked()

    async def prune_run_history(self, max_history_per_user: int, max_history_global: int) -> None:
        async with self._lock:
            runs = _read_dict(self._data.get("runs"))
            before = len(runs)
            self._prune_runs_locked(runs, max_history_per_user, max_history_global)
            if len(runs) != before:
                self._data["runs"] = runs
                await self._save_locked()

    async def list_run_tasks(self, user: UserRef, limit: int) -> list[dict[str, Any]]:
        async with self._lock:
            runs = _read_dict(self._data.get("runs"))
            items = [
                dict(item)
                for item in runs.values()
                if isinstance(item, dict)
                and item.get("user_key") == user.user_key
                and _run_visible_in_origin(item, user)
            ]
            items.sort(key=lambda item: float(item.get("started_at") or 0), reverse=True)
            return items[: max(1, min(limit, 50))]

    async def get_run_task(self, user: UserRef, run_id: str) -> tuple[dict[str, Any] | None, str | None]:
        if not RUN_ID_RE.fullmatch(run_id):
            return None, "任务编号格式不合法。"
        async with self._lock:
            item = _read_dict(self._data.get("runs")).get(run_id)
            if not isinstance(item, dict):
                return None, f"没有找到任务 #{run_id}。"
            if item.get("user_key") != user.user_key:
                return None, "只能查看或操作自己发起的 CloudCLI 任务。"
            if not _run_visible_in_origin(item, user):
                return None, "只能在发起任务的聊天会话中查看或操作该任务。"
            return dict(item), None

    async def mark_interrupted_runs(self, reason: str) -> int:
        async with self._lock:
            runs = _read_dict(self._data.get("runs"))
            now = time.time()
            changed = 0
            for item in runs.values():
                if not isinstance(item, dict):
                    continue
                status = _read_str(item.get("status"))
                if status not in {"running", "queued", "pending"}:
                    continue
                item["status"] = "interrupted"
                item["updated_at"] = now
                item["finished_at"] = now
                log = _read_dict_list(item.get("log"))
                log.append({"ts": now, "text": safe_text(reason, MAX_STORED_TEXT)})
                item["log"] = log[-MAX_RUN_LOG_ITEMS:]
                changed += 1
            if changed:
                self._data["runs"] = runs
                await self._save_locked()
            return changed

    async def append_audit(
        self,
        *,
        user: UserRef | None,
        action: str,
        approval: PendingApproval,
        reason: str = "",
        result: str = "sent",
    ) -> None:
        async with self._lock:
            audit = _read_dict_list(self._data.get("audit"))
            audit.append(
                {
                    "ts": time.time(),
                    "user_key": user.user_key if user else "system",
                    "display_name": user.display_name if user else "system",
                    "origin": _origin_key(user) if user else "",
                    "action": safe_text(action, 40),
                    "result": safe_text(result, 80),
                    "request_id": approval.request_id,
                    "session_id": approval.session_id,
                    "tool_name": approval.tool_name,
                    "provider": approval.provider,
                    "reason": safe_text(reason, 500),
                    "input_summary": safe_text(compact_json(approval.input_data), 500),
                }
            )
            self._data["audit"] = audit[-MAX_AUDIT_ITEMS:]
            await self._save_locked()

    async def list_audit(self, user: UserRef, limit: int) -> list[dict[str, Any]]:
        async with self._lock:
            entry = self._user_entry(user.user_key)
            origin = _origin_key(user)
            bindings = set(_bindings_for_origin(entry, origin))
            audit = _read_dict_list(self._data.get("audit"))
            items = [
                dict(item)
                for item in audit
                if (
                    item.get("user_key") == user.user_key
                    and _audit_origin_visible(item, entry, origin)
                )
                or (
                    item.get("user_key") == "system"
                    and bindings
                    and item.get("session_id") in bindings
                )
            ]
            items.sort(key=lambda item: float(item.get("ts") or 0), reverse=True)
            return items[: max(1, min(limit, 50))]

    def _user_entry(self, user_key: str) -> dict[str, Any]:
        users = _read_dict(self._data.get("users"))
        self._data["users"] = users
        entry = users.setdefault(
            user_key,
            {
                "display_name": "",
                "origins": [],
                "bindings": [],
                "binding_origins": {},
                "last_seen_at": 0,
                "session_index": [],
                "session_index_at": 0,
                "session_indexes": {},
            },
        )
        if not isinstance(entry, dict):
            entry = {
                "display_name": "",
                "origins": [],
                "bindings": [],
                "binding_origins": {},
                "last_seen_at": 0,
                "session_index": [],
                "session_index_at": 0,
                "session_indexes": {},
            }
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

    def _guess_next_run_id(self, runs: dict[str, Any]) -> int:
        ids = [int(key) for key in runs if isinstance(key, str) and RUN_ID_RE.fullmatch(key)]
        return max(ids, default=0) + 1

    async def _claim_pending_locked(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        pending = _read_dict(self._data.get("pending"))
        key = pending_storage_key(session_id, request_id)
        item = pending.get(key)
        approval = self._pending_from_record(item)
        if approval is None:
            return None, "当前没有待审批权限，可能已经被处理。"
        claimed_by = _read_str(item.get("claimed_by")) if isinstance(item, dict) else ""
        if claimed_by:
            return None, "该审批请求正在被处理，请稍后执行 /cloudcli pending 刷新。"
        item["claimed_by"] = safe_text(actor, 200)
        item["claimed_action"] = safe_text(action, 40)
        item["claimed_at"] = time.time()
        pending[key] = item
        self._data["pending"] = pending
        await self._save_locked()
        return approval, None

    def _visible_pending_locked(self, bindings: list[str], max_items: int) -> list[PendingApproval]:
        if not bindings:
            return []
        pending = _read_dict(self._data.get("pending"))
        approvals = []
        for item in pending.values():
            if not isinstance(item, dict):
                continue
            if _read_str(item.get("session_id")) not in bindings:
                continue
            approval = self._pending_from_record(item)
            if approval is not None:
                approvals.append(approval)
        approvals.sort(key=lambda item: (item.received_at, item.request_id))
        if max_items < 1:
            max_items = 1
        return approvals[:max_items]

    def _pending_from_record(self, item: Any) -> PendingApproval | None:
        if not isinstance(item, dict) or item.get("resolved") is True:
            return None
        session_id = _read_str(item.get("session_id"))
        request_id = _read_str(item.get("request_id"))
        if not is_valid_session_id(session_id) or not is_valid_request_id(request_id):
            return None
        return PendingApproval(
            request_id=request_id,
            session_id=session_id,
            tool_name=_read_str(item.get("tool_name")) or "UnknownTool",
            input_data=item.get("input_data"),
            provider=_read_str(item.get("provider")) or "claude",
            received_at=float(item.get("received_at") or 0),
        )

    def _pending_record(self, approval: PendingApproval, existing: Any = None) -> dict[str, Any]:
        record = {
            "request_id": approval.request_id,
            "session_id": approval.session_id,
            "tool_name": safe_inline_text(approval.tool_name, 120) or "UnknownTool",
            "input_data": safe_json_value(approval.input_data),
            "provider": safe_inline_text(approval.provider, 60) or "claude",
            "received_at": approval.received_at or time.time(),
            "resolved": False,
        }
        if isinstance(existing, dict):
            for field in PENDING_CLAIM_FIELDS:
                if existing.get(field):
                    record[field] = existing[field]
        return record

    def _prune_runs_locked(
        self,
        runs: dict[str, Any],
        max_history_per_user: int,
        max_history_global: int,
    ) -> None:
        removable = [
            (str(run_id), item)
            for run_id, item in runs.items()
            if isinstance(item, dict)
            and _read_str(item.get("status")) not in {"running", "queued", "pending"}
        ]
        if max_history_per_user > 0:
            by_user: dict[str, list[tuple[str, dict[str, Any]]]] = {}
            for run_id, item in removable:
                by_user.setdefault(_read_str(item.get("user_key")), []).append((run_id, item))
            for items in by_user.values():
                items.sort(key=lambda pair: float(pair[1].get("started_at") or 0), reverse=True)
                for run_id, _item in items[max_history_per_user:]:
                    runs.pop(run_id, None)

        if max_history_global > 0:
            remaining = [
                (str(run_id), item)
                for run_id, item in runs.items()
                if isinstance(item, dict)
                and _read_str(item.get("status")) not in {"running", "queued", "pending"}
            ]
            remaining.sort(key=lambda pair: float(pair[1].get("started_at") or 0), reverse=True)
            for run_id, _item in remaining[max_history_global:]:
                runs.pop(run_id, None)

    async def _save_locked(self) -> None:
        self.store.write(self._data)


def resolve_data_path(plugin_file: str, plugin_name: str) -> Path:
    env_path = os.getenv("ASTRBOT_DATA_PATH") or os.getenv("ASTRBOT_DATA_DIR")
    if env_path:
        return Path(env_path) / "plugins" / plugin_name

    plugin_dir = Path(plugin_file).resolve().parent
    for parent in plugin_dir.parents:
        if parent.name == "data" and (parent / "plugins").exists():
            return parent / "plugin_data" / plugin_name

    return plugin_dir / ".runtime_data"


def _normalize_pending_records(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(item, dict):
            continue
        session_id = _read_str(item.get("session_id"))
        request_id = _read_str(item.get("request_id"))
        if not request_id and isinstance(key, str):
            request_id = key.split("|", 1)[-1]
        storage_key = pending_storage_key(session_id, request_id)
        if not storage_key:
            continue
        normalized = {
            "request_id": request_id,
            "session_id": session_id,
            "tool_name": safe_inline_text(item.get("tool_name"), 120) or "UnknownTool",
            "input_data": safe_json_value(item.get("input_data")),
            "provider": safe_inline_text(item.get("provider"), 60) or "claude",
            "received_at": _parse_timestamp(item.get("received_at")) or time.time(),
            "resolved": bool(item.get("resolved") is True),
        }
        normalized["session_id"] = session_id
        normalized["request_id"] = request_id
        for field in PENDING_CLAIM_FIELDS:
            normalized.pop(field, None)
        result[storage_key] = normalized
    return result


def _normalize_run_records(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        run_id = _read_str(key)
        if not RUN_ID_RE.fullmatch(run_id) or not isinstance(item, dict):
            continue
        normalized = {
            "id": run_id,
            "user_key": safe_text(item.get("user_key"), 200),
            "display_name": safe_text(item.get("display_name"), 160),
            "origin": safe_text(item.get("origin"), 500),
            "status": safe_text(item.get("status"), 40) or "unknown",
            "provider": safe_text(item.get("provider"), 60) or "claude",
            "session_id": safe_text(item.get("session_id"), 200),
            "project_path": safe_text(item.get("project_path"), 500),
            "github_url": safe_text(item.get("github_url"), 500),
            "target": safe_text(item.get("target"), 500),
            "message": safe_text(item.get("message"), MAX_STORED_TEXT),
            "started_at": _parse_timestamp(item.get("started_at")),
            "updated_at": _parse_timestamp(item.get("updated_at")),
            "finished_at": _parse_timestamp(item.get("finished_at")),
            "log": _normalize_run_log(item.get("log")),
            "summary": safe_json_value(item.get("summary")),
        }
        if item.get("error"):
            normalized["error"] = safe_text(item.get("error"), MAX_STORED_TEXT)
        result[run_id] = normalized
    return result


def _normalize_run_log(value: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in _read_dict_list(value):
        items.append(
            {
                "ts": _parse_timestamp(item.get("ts")),
                "text": safe_text(item.get("text"), MAX_STORED_TEXT),
            }
        )
    return items[-MAX_RUN_LOG_ITEMS:]


def _normalize_audit_records(value: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in _read_dict_list(value):
        records.append(
            {
                "ts": _parse_timestamp(item.get("ts")),
                "user_key": safe_text(item.get("user_key"), 200),
                "display_name": safe_text(item.get("display_name"), 160),
                "origin": safe_text(item.get("origin"), 500),
                "action": safe_text(item.get("action"), 40),
                "result": safe_text(item.get("result"), 80),
                "request_id": safe_text(item.get("request_id"), 200),
                "session_id": safe_text(item.get("session_id"), 200),
                "tool_name": safe_text(item.get("tool_name"), 120),
                "provider": safe_text(item.get("provider"), 60) or "claude",
                "reason": safe_text(item.get("reason"), 500),
                "input_summary": safe_text(item.get("input_summary"), 500),
            }
        )
    return records


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _origin_key(user: UserRef | None) -> str:
    if user is None:
        return ""
    return user.unified_msg_origin or "__default__"


def _bindings_for_origin(entry: dict[str, Any], origin: str) -> list[str]:
    binding_origins = _read_origin_map(entry.get("binding_origins"))
    return sorted(
        session_id
        for session_id, origins in binding_origins.items()
        if origin in origins
    )


def _read_session_indexes(value: Any) -> dict[str, dict[str, Any]]:
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


def _session_index_for_origin(entry: dict[str, Any], origin: str) -> list[dict[str, Any]]:
    scoped = _read_session_indexes(entry.get("session_indexes")).get(origin)
    if isinstance(scoped, dict):
        return _read_dict_list(scoped.get("items"))
    return []


def _run_visible_in_origin(item: dict[str, Any], user: UserRef) -> bool:
    return _read_str(item.get("origin")) == _origin_key(user)


def _audit_origin_visible(item: dict[str, Any], entry: dict[str, Any], origin: str) -> bool:
    item_origin = _read_str(item.get("origin"))
    if item_origin:
        return item_origin == origin
    origins = _read_list(entry.get("origins"))
    return len(origins) == 1 and origins[0] == origin


def _read_origin_map(value: Any) -> dict[str, list[str]]:
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


def _read_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _read_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


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
