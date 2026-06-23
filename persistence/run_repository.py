"""CloudCLI agent 任务历史仓库。"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

try:
    from ..core.sanitizer import safe_json_value, safe_text
    from .state_models import UserRef, is_valid_session_id
    from .user_repository import origin_key
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.sanitizer import safe_json_value, safe_text
    from persistence.state_models import UserRef, is_valid_session_id
    from persistence.user_repository import origin_key


RUN_ID_RE = re.compile(r"^[0-9]{1,12}$")
MAX_RUN_LOG_ITEMS = 80
DEFAULT_MAX_RUN_HISTORY_PER_USER = 50
DEFAULT_MAX_RUN_HISTORY_GLOBAL = 500
MAX_STORED_TEXT = 1200


class RunRepository:
    """只操作状态字典中的 `runs` 区域，不负责加锁和落盘。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def create_task(
        self,
        user: UserRef,
        payload: dict[str, Any],
        display_target: str,
        *,
        message_for_storage: Callable[[Any], str],
        max_history_per_user: int = DEFAULT_MAX_RUN_HISTORY_PER_USER,
        max_history_global: int = DEFAULT_MAX_RUN_HISTORY_GLOBAL,
    ) -> str:
        """创建一条本地任务记录，并返回自增任务编号。"""
        run_id = str(_read_positive_int(self.data.get("next_run_id"), 1))
        self.data["next_run_id"] = int(run_id) + 1
        runs = _read_dict(self.data.get("runs"))
        now = time.time()
        runs[run_id] = {
            "id": run_id,
            "user_key": user.user_key,
            "display_name": user.display_name,
            "origin": origin_key(user),
            "status": "running",
            "provider": safe_text(payload.get("provider"), 60) or "claude",
            "session_id": safe_text(payload.get("sessionId"), 200),
            "project_path": safe_text(payload.get("projectPath"), 500),
            "github_url": safe_text(payload.get("githubUrl"), 500),
            "target": safe_text(display_target, 500),
            "message": message_for_storage(payload.get("message")),
            "started_at": now,
            "updated_at": now,
            "finished_at": 0,
            "log": [],
            "summary": {},
        }
        # 创建新任务时顺手裁剪历史，避免状态文件随着长期使用无限增长。
        self.prune(runs, max_history_per_user, max_history_global)
        self.data["runs"] = runs
        return run_id

    def update_task(
        self,
        run_id: str,
        *,
        status: str | None = None,
        event: str | None = None,
        session_id: str | None = None,
        summary: dict[str, Any] | None = None,
        summary_for_storage: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        error: str | None = None,
        finished: bool = False,
    ) -> bool:
        """更新任务状态、日志、sessionId、摘要或错误信息。"""
        if not RUN_ID_RE.fullmatch(run_id):
            return False
        runs = _read_dict(self.data.get("runs"))
        item = runs.get(run_id)
        if not isinstance(item, dict):
            return False
        now = time.time()
        if status:
            item["status"] = safe_text(status, 40)
        if session_id and is_valid_session_id(session_id):
            item["session_id"] = session_id
        if summary is not None:
            stored_summary = summary_for_storage(summary) if summary_for_storage else summary
            item["summary"] = safe_json_value(stored_summary)
        if error:
            item["error"] = safe_text(error, MAX_STORED_TEXT)
        if event:
            log = _read_dict_list(item.get("log"))
            log.append({"ts": now, "text": safe_text(event, MAX_STORED_TEXT)})
            # 只保留最近日志，完整输出不应无限写入本地状态文件。
            item["log"] = log[-MAX_RUN_LOG_ITEMS:]
        if finished:
            item["finished_at"] = now
        item["updated_at"] = now
        runs[run_id] = item
        self.data["runs"] = runs
        return True

    def prune_history(self, max_history_per_user: int, max_history_global: int) -> bool:
        """按用户和全局上限裁剪已结束任务历史。"""
        runs = _read_dict(self.data.get("runs"))
        before = len(runs)
        self.prune(runs, max_history_per_user, max_history_global)
        if len(runs) != before:
            self.data["runs"] = runs
            return True
        return False

    def list_tasks(self, user: UserRef, limit: int) -> list[dict[str, Any]]:
        """列出当前用户在当前聊天 origin 可见的任务。"""
        runs = _read_dict(self.data.get("runs"))
        items = [
            dict(item)
            for item in runs.values()
            if isinstance(item, dict)
            and item.get("user_key") == user.user_key
            and run_visible_in_origin(item, user)
        ]
        items.sort(key=lambda item: float(item.get("started_at") or 0), reverse=True)
        return items[: max(1, min(limit, 50))]

    def get_task(self, user: UserRef, run_id: str) -> tuple[dict[str, Any] | None, str | None]:
        """读取单个任务，并限制只能在发起任务的同一聊天会话中查看/操作。"""
        if not RUN_ID_RE.fullmatch(run_id):
            return None, "任务编号格式不合法。"
        item = _read_dict(self.data.get("runs")).get(run_id)
        if not isinstance(item, dict):
            return None, f"没有找到任务 #{run_id}。"
        if item.get("user_key") != user.user_key:
            return None, "只能查看或操作自己发起的 CloudCLI 任务。"
        if not run_visible_in_origin(item, user):
            return None, "只能在发起任务的聊天会话中查看或操作该任务。"
        return dict(item), None

    def mark_interrupted(self, reason: str) -> int:
        """插件重启时把还在 running/queued/pending 的本地任务标成 interrupted。"""
        runs = _read_dict(self.data.get("runs"))
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
            self.data["runs"] = runs
        return changed

    def scrub_sensitive(self, omitted_text: str) -> None:
        """关闭敏感状态持久化时，清除历史任务中的用户 prompt 和助手摘要。"""
        runs = _read_dict(self.data.get("runs"))
        for item in runs.values():
            if not isinstance(item, dict):
                continue
            item["message"] = omitted_text
            summary = item.get("summary")
            if isinstance(summary, dict) and summary.get("assistantText"):
                summary["assistantText"] = omitted_text
                item["summary"] = summary
        self.data["runs"] = runs

    def prune(
        self,
        runs: dict[str, Any],
        max_history_per_user: int,
        max_history_global: int,
    ) -> None:
        """在传入的 runs 字典上原地裁剪已结束任务。"""
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


def normalize_run_records(value: dict[str, Any]) -> dict[str, Any]:
    """加载状态文件时清洗任务记录，丢弃非法 run_id 和异常字段。"""
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


def guess_next_run_id(runs: dict[str, Any]) -> int:
    """根据已有任务编号推断下一个自增 ID。"""
    ids = [int(key) for key in runs if isinstance(key, str) and RUN_ID_RE.fullmatch(key)]
    return max(ids, default=0) + 1


def run_visible_in_origin(item: dict[str, Any], user: UserRef) -> bool:
    """任务只能在创建它的聊天 origin 中查看和取消。"""
    return _read_str(item.get("origin")) == origin_key(user)


def _normalize_run_log(value: Any) -> list[dict[str, Any]]:
    """清洗任务日志并截断到最近 MAX_RUN_LOG_ITEMS 条。"""
    items: list[dict[str, Any]] = []
    for item in _read_dict_list(value):
        items.append(
            {
                "ts": _parse_timestamp(item.get("ts")),
                "text": safe_text(item.get("text"), MAX_STORED_TEXT),
            }
        )
    return items[-MAX_RUN_LOG_ITEMS:]


def _read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _read_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


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
