"""运行中 CloudCLI agent 任务的内存配额控制。"""

from __future__ import annotations

from collections import Counter

import asyncio


class RunQuota:
    """限制单用户和全局并发任务数，防止聊天命令刷爆 CloudCLI。"""

    def __init__(self, per_user_limit: int, global_limit: int) -> None:
        self.per_user_limit = per_user_limit
        self.global_limit = global_limit
        self._active_by_user: Counter[str] = Counter()
        self._active_total = 0

    def try_acquire(self, user_key: str) -> str:
        """尝试占用一个任务配额；返回空字符串表示成功。"""
        if self.global_limit > 0 and self._active_total >= self.global_limit:
            return f"当前 CloudCLI 任务数已达全局上限 {self.global_limit}，请稍后再试。"
        if self.per_user_limit > 0 and self._active_by_user[user_key] >= self.per_user_limit:
            return f"当前用户的 CloudCLI 任务数已达上限 {self.per_user_limit}，请等待已有任务完成。"
        self._active_by_user[user_key] += 1
        self._active_total += 1
        return ""

    def release(self, user_key: str) -> None:
        """任务结束、失败或取消后释放配额。"""
        if self._active_by_user[user_key] > 0:
            self._active_by_user[user_key] -= 1
            if self._active_by_user[user_key] <= 0:
                self._active_by_user.pop(user_key, None)
        if self._active_total > 0:
            self._active_total -= 1


class RunRuntimeRegistry:
    """In-memory lifecycle state for currently running agent tasks.

    Persistent task history lives in `PluginState`; this registry only tracks
    process-local objects and one-shot control flags that cannot survive restart.
    """

    def __init__(self) -> None:
        self._tasks_by_id: dict[str, asyncio.Task] = {}
        self._cancel_requested_ids: set[str] = set()
        self._abort_sent_ids: set[str] = set()

    def track_task(self, run_id: str, task: asyncio.Task) -> None:
        self._tasks_by_id[run_id] = task

    def get_task(self, run_id: str) -> asyncio.Task | None:
        return self._tasks_by_id.get(run_id)

    def remove_task(self, run_id: str) -> None:
        self._tasks_by_id.pop(run_id, None)

    def request_cancel(self, run_id: str) -> None:
        self._cancel_requested_ids.add(run_id)

    def cancel_requested(self, run_id: str) -> bool:
        return run_id in self._cancel_requested_ids

    def mark_abort_sent_once(self, run_id: str) -> bool:
        if not run_id:
            return True
        if run_id in self._abort_sent_ids:
            return False
        self._abort_sent_ids.add(run_id)
        return True

    def release_abort_sent(self, run_id: str) -> None:
        self._abort_sent_ids.discard(run_id)

    def clear_run(self, run_id: str) -> None:
        self._cancel_requested_ids.discard(run_id)
        self._abort_sent_ids.discard(run_id)
