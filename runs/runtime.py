from __future__ import annotations

from collections import Counter


class RunQuota:
    def __init__(self, per_user_limit: int, global_limit: int) -> None:
        self.per_user_limit = per_user_limit
        self.global_limit = global_limit
        self._active_by_user: Counter[str] = Counter()
        self._active_total = 0

    def try_acquire(self, user_key: str) -> str:
        if self.global_limit > 0 and self._active_total >= self.global_limit:
            return f"当前 CloudCLI 任务数已达全局上限 {self.global_limit}，请稍后再试。"
        if self.per_user_limit > 0 and self._active_by_user[user_key] >= self.per_user_limit:
            return f"当前用户的 CloudCLI 任务数已达上限 {self.per_user_limit}，请等待已有任务完成。"
        self._active_by_user[user_key] += 1
        self._active_total += 1
        return ""

    def release(self, user_key: str) -> None:
        if self._active_by_user[user_key] > 0:
            self._active_by_user[user_key] -= 1
            if self._active_by_user[user_key] <= 0:
                self._active_by_user.pop(user_key, None)
        if self._active_total > 0:
            self._active_total -= 1
