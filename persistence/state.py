"""插件状态门面：统一加锁、落盘、敏感信息处理和各 repository 的组合调用。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

try:
    from ..core.sanitizer import compact_json, safe_json_value, safe_text
    from .audit_repository import AuditRepository, MAX_AUDIT_ITEMS, normalize_audit_records
    from .state_models import (
        PendingApproval,
        UserRef,
        is_valid_session_id,
        pending_storage_key,
    )
    from .pending_repository import PendingApprovalRepository, normalize_pending_records
    from .run_repository import (
        DEFAULT_MAX_RUN_HISTORY_GLOBAL,
        DEFAULT_MAX_RUN_HISTORY_PER_USER,
        RUN_ID_RE,
        RunRepository,
        guess_next_run_id,
        normalize_run_records,
    )
    from .state_storage import JsonStateStore, StateProcessLock
    from .user_repository import (
        MAX_SESSION_INDEX_ITEMS,
        UserStateRepository,
        bindings_for_origin,
        origin_key,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import compact_json, safe_json_value, safe_text
    from persistence.audit_repository import AuditRepository, MAX_AUDIT_ITEMS, normalize_audit_records
    from persistence.pending_repository import PendingApprovalRepository, normalize_pending_records
    from persistence.run_repository import (
        DEFAULT_MAX_RUN_HISTORY_GLOBAL,
        DEFAULT_MAX_RUN_HISTORY_PER_USER,
        RUN_ID_RE,
        RunRepository,
        guess_next_run_id,
        normalize_run_records,
    )
    from persistence.state_models import (
        PendingApproval,
        UserRef,
        is_valid_session_id,
        pending_storage_key,
    )
    from persistence.state_storage import JsonStateStore, StateProcessLock
    from persistence.user_repository import (
        MAX_SESSION_INDEX_ITEMS,
        UserStateRepository,
        bindings_for_origin,
        origin_key,
    )

MAX_STORED_TEXT = 1200
OMITTED_SENSITIVE_TEXT = "[omitted by persist_sensitive_state=false]"
OMITTED_SENSITIVE_INPUT = {
    "notice": "approval input is kept only in memory unless persist_sensitive_state is enabled"
}
DEFAULT_SAVE_BATCH_DELAY_SECONDS = 1.0
logger = logging.getLogger(__name__)


class PluginState:
    """线程安全/协程安全的状态服务，是业务层读写 JSON 状态的唯一入口。"""

    def __init__(
        self,
        path: Path,
        *,
        persist_sensitive_state: bool = False,
        exclusive_runtime_lock: bool = False,
    ) -> None:
        """初始化内存状态；调用 load() 后才会读取磁盘文件。"""
        self.path = path
        self.store = JsonStateStore(path)
        self.persist_sensitive_state = persist_sensitive_state
        self.exclusive_runtime_lock = exclusive_runtime_lock
        self._runtime_lock: StateProcessLock | None = None
        self._pending_input_cache: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._save_pending = False
        self._scheduled_save_task: asyncio.Task | None = None
        self._save_batch_delay_seconds = DEFAULT_SAVE_BATCH_DELAY_SECONDS
        self._data: dict[str, Any] = {
            "version": 3,
            "users": {},
            "pending": {},
            "runs": {},
            "audit": [],
            "next_run_id": 1,
        }

    async def load(self) -> None:
        """加载状态文件；损坏时备份旧文件并重新初始化。"""
        async with self._lock:
            if self.exclusive_runtime_lock and self._runtime_lock is None:
                self._runtime_lock = self.store.acquire_process_lock()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                await self._save_locked()
                return
            try:
                loaded = self.store.read()
                if isinstance(loaded, dict):
                    # 每次加载都做 schema 归一化，兼容旧版本状态文件和手工编辑过的文件。
                    self._data["version"] = 3
                    self._data["users"] = _read_dict(loaded.get("users"))
                    self._data["pending"] = normalize_pending_records(_read_dict(loaded.get("pending")))
                    self._data["runs"] = normalize_run_records(_read_dict(loaded.get("runs")))
                    self._data["audit"] = normalize_audit_records(loaded.get("audit"))[-MAX_AUDIT_ITEMS:]
                    self._data["next_run_id"] = _read_positive_int(
                        loaded.get("next_run_id"),
                        guess_next_run_id(self._data["runs"]),
                    )
                    if not self.persist_sensitive_state:
                        # 如果当前配置禁止敏感持久化，启动时立刻清理旧状态里的敏感字段。
                        self._scrub_sensitive_state_locked()
                        await self._save_locked()
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

    async def flush(self) -> None:
        """立即写出延迟保存的状态，通常在插件退出时调用。"""
        task = self._scheduled_save_task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            self._scheduled_save_task = None
            if self._save_pending:
                self.store.write(self._data)
                self._save_pending = False

    async def close(self) -> None:
        """刷新状态并释放运行期独占锁，供插件卸载时调用。"""
        await self.flush()
        if self._runtime_lock is not None:
            self._runtime_lock.release()
            self._runtime_lock = None

    async def remember_user(self, user: UserRef) -> None:
        """记录用户身份和最近 origin。"""
        async with self._lock:
            self._users_locked().remember_user(user)
            await self._save_locked()

    async def bind_session(
        self,
        user: UserRef,
        session_id: str,
        max_bindings: int,
    ) -> tuple[bool, str]:
        """绑定 session 到当前用户和当前聊天 origin。"""
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        if max_bindings < 1:
            max_bindings = 1
        async with self._lock:
            changed, message = self._users_locked().bind_session(user, session_id, max_bindings)
            await self._save_locked()
            return changed, message

    async def unbind_session(self, user: UserRef, session_id: str) -> tuple[bool, str]:
        """解除当前 origin 对某个 session 的绑定。"""
        if not is_valid_session_id(session_id):
            return False, "sessionId 格式不合法。"
        async with self._lock:
            changed, message = self._users_locked().unbind_session(user, session_id)
            await self._save_locked()
            return changed, message

    async def unbind_all(self, user: UserRef) -> tuple[bool, str]:
        """解除当前 origin 下所有 session 绑定。"""
        async with self._lock:
            changed, message = self._users_locked().unbind_all(user)
            await self._save_locked()
            return changed, message

    async def list_bindings(self, user: UserRef) -> list[str]:
        """列出当前 origin 的绑定 session。"""
        async with self._lock:
            return self._users_locked().list_bindings(user)

    async def has_binding(self, user: UserRef, session_id: str) -> bool:
        """判断当前 origin 是否绑定指定 session。"""
        if not is_valid_session_id(session_id):
            return False
        async with self._lock:
            return self._users_locked().has_binding(user, session_id)

    async def remember_session_index(
        self,
        user: UserRef,
        sessions: list[dict[str, Any]],
        max_items: int = MAX_SESSION_INDEX_ITEMS,
    ) -> None:
        """保存最近 session 序号缓存；敏感持久化关闭时只保留必要字段。"""
        async with self._lock:
            self._users_locked().remember_session_index(
                user,
                self._session_index_for_storage(sessions),
                max_items,
            )
            await self._save_locked()

    async def find_session_index_item(self, user: UserRef, session_id: str) -> dict[str, str] | None:
        """在当前 origin 的序号缓存中查找 session。"""
        if not is_valid_session_id(session_id):
            return None
        async with self._lock:
            return self._users_locked().find_session_index_item(user, session_id)
        return None

    async def resolve_session_ref(
        self,
        user: UserRef,
        ref: str,
    ) -> tuple[dict[str, str] | None, str | None]:
        """把用户输入的 session 引用解析为 session 字典。"""
        async with self._lock:
            return self._users_locked().resolve_session_ref(user, ref)

    async def users_bound_to_session(self, session_id: str) -> list[dict[str, Any]]:
        """查找绑定了该 session 的用户和 origin，用于主动推送。"""
        async with self._lock:
            return self._users_locked().users_bound_to_session(session_id)

    async def upsert_pending(self, approval: PendingApproval) -> None:
        """新增或更新待审批请求；敏感输入默认只放内存缓存。"""
        async with self._lock:
            self._remember_pending_input_locked(approval)
            if self._pending_repo_locked().upsert(self._approval_for_storage(approval)):
                await self._save_locked()

    async def remove_pending(self, session_id: str, request_id: str) -> None:
        """删除待审批请求并清理对应内存输入缓存。"""
        async with self._lock:
            self._pending_input_cache.pop(pending_storage_key(session_id, request_id), None)
            self._pending_repo_locked().remove(session_id, request_id)
            await self._save_locked()

    async def get_pending(self, session_id: str, request_id: str) -> PendingApproval | None:
        """读取待审批请求，并在可能时补回内存中的原始输入。"""
        async with self._lock:
            return self._with_cached_pending_input(
                self._pending_repo_locked().get(session_id, request_id)
            )

    async def list_pending(self) -> list[PendingApproval]:
        """列出所有待审批请求，并补回内存中的原始输入。"""
        async with self._lock:
            return self._with_cached_pending_inputs(self._pending_repo_locked().list())

    async def merge_pending(self, approvals: list[PendingApproval]) -> None:
        """把远端审批合并进本地缓存。"""
        async with self._lock:
            for approval in approvals:
                self._remember_pending_input_locked(approval)
            self._pending_repo_locked().merge(
                [self._approval_for_storage(approval) for approval in approvals]
            )
            await self._save_locked()

    async def replace_pending_for_session(
        self,
        session_id: str,
        approvals: list[PendingApproval],
        *,
        preserve_unconfirmed: bool = True,
    ) -> list[str]:
        """用远端列表替换某个 session 的 pending，并返回被移除的 storage key。"""
        async with self._lock:
            for approval in approvals:
                self._remember_pending_input_locked(approval)
            removed = self._pending_repo_locked().replace_for_session(
                session_id,
                [self._approval_for_storage(approval) for approval in approvals],
                preserve_unconfirmed=preserve_unconfirmed,
            )
            for key in removed:
                self._pending_input_cache.pop(key, None)
            await self._save_locked()
            return removed

    async def visible_pending_for_user(
        self,
        user: UserRef,
        max_items: int,
    ) -> list[PendingApproval]:
        """列出当前用户当前 origin 绑定 session 中可见的待审批请求。"""
        async with self._lock:
            entry = self._users_locked().entry(user.user_key)
            bindings = bindings_for_origin(entry, origin_key(user))
            return self._with_cached_pending_inputs(
                self._pending_repo_locked().visible_for_bindings(bindings, max_items)
            )

    async def resolve_visible_request(
        self,
        user: UserRef,
        request_no: int | None,
        max_items: int,
    ) -> tuple[PendingApproval | None, str | None]:
        """按用户可见列表解析审批序号；只有一条时允许省略序号。"""
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
        """占用当前用户可见的一条审批，防止重复处理。"""
        async with self._lock:
            entry = self._users_locked().entry(user.user_key)
            bindings = bindings_for_origin(entry, origin_key(user))
            repo = self._pending_repo_locked()
            visible = repo.visible_for_bindings(bindings, max_items)
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
            result = repo.claim(
                approval.session_id,
                approval.request_id,
                actor=user.user_key,
                action=action,
            )
            await self._save_locked()
            claimed, error = result
            return self._with_cached_pending_input(claimed), error

    async def claim_pending(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        """按 session/requestId 直接占用一条审批，主要给超时 worker 使用。"""
        async with self._lock:
            result = self._pending_repo_locked().claim(
                session_id,
                request_id,
                actor=actor,
                action=action,
            )
            await self._save_locked()
            claimed, error = result
            return self._with_cached_pending_input(claimed), error

    async def release_pending_claim(self, session_id: str, request_id: str, actor: str) -> None:
        """释放指定 actor 持有的审批 claim。"""
        async with self._lock:
            if self._pending_repo_locked().release_claim(session_id, request_id, actor):
                await self._save_locked()

    async def mark_pending_decision_unconfirmed(
        self,
        session_id: str,
        request_id: str,
        *,
        actor: str,
        action: str,
        error: str,
    ) -> None:
        """记录审批决定已发送但远端未确认的中间态。"""
        async with self._lock:
            if self._pending_repo_locked().mark_decision_unconfirmed(
                session_id,
                request_id,
                actor=actor,
                action=action,
                error=error,
            ):
                await self._save_locked()

    async def create_run_task(
        self,
        user: UserRef,
        payload: dict[str, Any],
        display_target: str,
        max_history_per_user: int = DEFAULT_MAX_RUN_HISTORY_PER_USER,
        max_history_global: int = DEFAULT_MAX_RUN_HISTORY_GLOBAL,
    ) -> str:
        """创建本地任务记录。"""
        async with self._lock:
            run_id = self._runs_locked().create_task(
                user,
                payload,
                display_target,
                message_for_storage=self._sensitive_text_for_storage,
                max_history_per_user=max_history_per_user,
                max_history_global=max_history_global,
            )
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
        """更新任务状态；普通流式日志可延迟批量写盘以降低 I/O。"""
        if not RUN_ID_RE.fullmatch(run_id):
            return
        async with self._lock:
            if self._runs_locked().update_task(
                run_id,
                status=status,
                event=event,
                session_id=session_id,
                summary=summary,
                summary_for_storage=self._summary_for_storage,
                error=error,
                finished=finished,
            ):
                await self._save_locked(
                    defer=self._can_defer_run_update(
                        status=status,
                        event=event,
                        session_id=session_id,
                        summary=summary,
                        error=error,
                        finished=finished,
                    )
                )

    async def prune_run_history(self, max_history_per_user: int, max_history_global: int) -> None:
        """按配置裁剪已结束任务历史。"""
        async with self._lock:
            if self._runs_locked().prune_history(max_history_per_user, max_history_global):
                await self._save_locked()

    async def list_run_tasks(self, user: UserRef, limit: int) -> list[dict[str, Any]]:
        """列出当前用户当前 origin 的任务历史。"""
        async with self._lock:
            return self._runs_locked().list_tasks(user, limit)

    async def get_run_task(self, user: UserRef, run_id: str) -> tuple[dict[str, Any] | None, str | None]:
        """读取单个任务并做用户/origin 可见性检查。"""
        async with self._lock:
            return self._runs_locked().get_task(user, run_id)

    async def mark_interrupted_runs(self, reason: str) -> int:
        """插件启动时把旧进程遗留的运行中任务标为 interrupted。"""
        async with self._lock:
            changed = self._runs_locked().mark_interrupted(reason)
            if changed:
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
        """追加审批审计记录。"""
        async with self._lock:
            self._audit_locked().append(
                user=user,
                action=action,
                approval=approval,
                reason=reason,
                result=result,
                input_summary=self._approval_input_summary_for_storage(approval),
            )
            await self._save_locked()

    async def list_audit(self, user: UserRef, limit: int) -> list[dict[str, Any]]:
        """列出当前用户和当前 origin 可见的审批审计记录。"""
        async with self._lock:
            entry = self._users_locked().entry(user.user_key)
            return self._audit_locked().list(user, entry, limit)

    def _approval_for_storage(self, approval: PendingApproval) -> PendingApproval:
        """按敏感状态配置决定审批输入是否允许写入磁盘。"""
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

    def _remember_pending_input_locked(self, approval: PendingApproval) -> None:
        """敏感持久化关闭时，把审批输入仅缓存在内存，供当前进程展示。"""
        key = pending_storage_key(approval.session_id, approval.request_id)
        if not key:
            return
        if self.persist_sensitive_state:
            self._pending_input_cache.pop(key, None)
            return
        self._pending_input_cache[key] = safe_json_value(approval.input_data)

    def _with_cached_pending_input(self, approval: PendingApproval | None) -> PendingApproval | None:
        """如果内存里有原始审批输入，就把落盘占位内容替换回去。"""
        if approval is None or self.persist_sensitive_state:
            return approval
        key = pending_storage_key(approval.session_id, approval.request_id)
        if not key or key not in self._pending_input_cache:
            return approval
        return PendingApproval(
            request_id=approval.request_id,
            session_id=approval.session_id,
            tool_name=approval.tool_name,
            input_data=self._pending_input_cache[key],
            provider=approval.provider,
            received_at=approval.received_at,
        )

    def _with_cached_pending_inputs(self, approvals: list[PendingApproval]) -> list[PendingApproval]:
        """批量补回内存审批输入。"""
        return [
            updated
            for approval in approvals
            if (updated := self._with_cached_pending_input(approval)) is not None
        ]

    def _sensitive_text_for_storage(self, value: Any) -> str:
        """决定任务 prompt 是否写入磁盘；默认只记录字符数。"""
        if self.persist_sensitive_state:
            return safe_text(value, MAX_STORED_TEXT)
        text = value if isinstance(value, str) else str(value or "")
        return f"{OMITTED_SENSITIVE_TEXT}; chars={len(text)}"

    def _approval_input_summary_for_storage(self, approval: PendingApproval) -> str:
        """决定审计记录中是否保存工具输入摘要。"""
        if self.persist_sensitive_state:
            return safe_text(compact_json(approval.input_data), 500)
        return OMITTED_SENSITIVE_TEXT

    def _summary_for_storage(self, summary: dict[str, Any]) -> dict[str, Any]:
        """决定任务最终助手文本是否写入磁盘。"""
        if self.persist_sensitive_state:
            return summary
        stored = dict(summary)
        if stored.get("assistantText"):
            stored["assistantText"] = OMITTED_SENSITIVE_TEXT
        return stored

    def _session_index_for_storage(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """决定最近 session 缓存可落盘字段；默认不保存项目路径和摘要。"""
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
        return stored_sessions

    def _scrub_sensitive_state_locked(self) -> None:
        """清理内存状态中已经存在的敏感字段，并准备覆盖写回磁盘。"""
        pending = _read_dict(self._data.get("pending"))
        for item in pending.values():
            if isinstance(item, dict):
                item["input_data"] = dict(OMITTED_SENSITIVE_INPUT)
        self._data["pending"] = pending

        self._runs_locked().scrub_sensitive(OMITTED_SENSITIVE_TEXT)
        self._audit_locked().scrub_sensitive(OMITTED_SENSITIVE_TEXT)

    def _pending_repo_locked(self) -> PendingApprovalRepository:
        """创建 pending repository；调用方必须已持有 `_lock`。"""
        return PendingApprovalRepository(self._data)

    def _users_locked(self) -> UserStateRepository:
        """创建 user repository；调用方必须已持有 `_lock`。"""
        return UserStateRepository(self._data)

    def _runs_locked(self) -> RunRepository:
        """创建 run repository；调用方必须已持有 `_lock`。"""
        return RunRepository(self._data)

    def _audit_locked(self) -> AuditRepository:
        """创建 audit repository；调用方必须已持有 `_lock`。"""
        return AuditRepository(self._data)

    def _can_defer_run_update(
        self,
        *,
        status: str | None,
        event: str | None,
        session_id: str | None,
        summary: dict[str, Any] | None,
        error: str | None,
        finished: bool,
    ) -> bool:
        """判断某次任务更新是否适合延迟批量保存。"""
        return (
            not finished
            and status is None
            and summary is None
            and error is None
            and (event is not None or session_id is not None)
        )

    async def _save_locked(self, *, defer: bool = False) -> None:
        """写状态文件；defer=True 时安排延迟保存。调用方必须已持有 `_lock`。"""
        if defer:
            self._schedule_save_locked()
            return
        if self._scheduled_save_task and not self._scheduled_save_task.done():
            self._scheduled_save_task.cancel()
        self._scheduled_save_task = None
        self.store.write(self._data)
        self._save_pending = False

    def _schedule_save_locked(self) -> None:
        """安排一次延迟保存，多个流式日志更新会合并成一次磁盘写入。"""
        self._save_pending = True
        task = self._scheduled_save_task
        if task and not task.done():
            return
        self._scheduled_save_task = asyncio.create_task(self._delayed_save())

    async def _delayed_save(self) -> None:
        """延迟保存 worker，到点后在锁内写出最新状态。"""
        try:
            delay = max(0.0, float(self._save_batch_delay_seconds))
            if delay > 0:
                await asyncio.sleep(delay)
            async with self._lock:
                if self._save_pending:
                    self.store.write(self._data)
                    self._save_pending = False
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Delayed CloudCLI connector state save failed.")
        finally:
            current = asyncio.current_task()
            if self._scheduled_save_task is current:
                self._scheduled_save_task = None


def resolve_data_path(plugin_file: str, plugin_name: str) -> Path:
    """解析插件数据目录，优先使用 AstrBot 数据环境变量，其次探测常见目录结构。"""
    env_path = os.getenv("ASTRBOT_DATA_PATH") or os.getenv("ASTRBOT_DATA_DIR")
    if env_path:
        return Path(env_path) / "plugins" / plugin_name

    plugin_dir = Path(plugin_file).resolve().parent
    for parent in plugin_dir.parents:
        if parent.name == "data" and (parent / "plugins").exists():
            return parent / "plugin_data" / plugin_name

    return plugin_dir / ".runtime_data"


def _read_dict(value: Any) -> dict[str, Any]:
    """只接受 dict，其他类型视为空。"""
    return value if isinstance(value, dict) else {}


def _read_positive_int(value: Any, default: int) -> int:
    """读取正整数，否则返回默认值。"""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
