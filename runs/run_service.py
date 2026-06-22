from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from ..cloudcli.cloudcli_client import CloudCLIClient, CloudCLIError
    from ..commands.command_parser import parse_positive_int
    from ..commands.formatting import (
        clip_text,
        extract_agent_text,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_run_log,
        format_run_tasks,
    )
    from ..core.config import ConnectorSettings
    from ..core.redaction import redact_exception_text, redact_text
    from ..persistence.state import PluginState
    from ..persistence.state_models import UserRef, is_valid_session_id
    from ..security.identity import missing_identity_message
    from .run_requests import RunRequestBuilder
    from .runtime import RunQuota
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_client import CloudCLIClient, CloudCLIError
    from commands.command_parser import parse_positive_int
    from commands.formatting import (
        clip_text,
        extract_agent_text,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_run_log,
        format_run_tasks,
    )
    from core.config import ConnectorSettings
    from core.redaction import redact_exception_text, redact_text
    from persistence.state import PluginState
    from persistence.state_models import UserRef, is_valid_session_id
    from runs.run_requests import RunRequestBuilder
    from runs.runtime import RunQuota
    from security.identity import missing_identity_message


SendProactive = Callable[[str, str], Awaitable[None]]
TrackTask = Callable[[asyncio.Task], None]
logger = logging.getLogger(__name__)


class _RunCancelledByUser(Exception):
    pass


class RunService:
    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        state: PluginState,
        client: CloudCLIClient,
        request_builder: RunRequestBuilder,
        quota: RunQuota,
        send_proactive: SendProactive,
        track_task: TrackTask,
    ) -> None:
        self.settings = settings
        self.state = state
        self.client = client
        self.request_builder = request_builder
        self.quota = quota
        self.send_proactive = send_proactive
        self.track_task = track_task
        self.run_tasks_by_id: dict[str, asyncio.Task] = {}
        self.cancel_requested_run_ids: set[str] = set()
        self.abort_sent_run_ids: set[str] = set()

    async def handle_run(self, user: UserRef, args: list[str]) -> str:
        if args and args[0] in {"list", "log", "cancel"}:
            return await self.handle_run_control(user, args)

        parsed, error = await self.request_builder.parse(user, args)
        if error:
            return error
        assert parsed is not None

        quota_error = self.quota.try_acquire(user.user_key)
        if quota_error:
            return quota_error
        try:
            run_id = await self.state.create_run_task(
                user,
                parsed.payload,
                parsed.display_target,
                self.settings.max_run_history_per_user,
                self.settings.max_run_history_global,
            )
        except Exception:
            self.quota.release(user.user_key)
            raise
        task = asyncio.create_task(
            self._run_agent_background(
                run_id,
                user.unified_msg_origin,
                parsed.payload,
            )
        )
        self.run_tasks_by_id[run_id] = task
        task.add_done_callback(
            lambda _task, task_id=run_id, user_key=user.user_key: self._on_run_task_done(task_id, user_key)
        )
        self.track_task(task)
        return format_agent_start_message(parsed.payload, run_id)

    async def handle_run_control(self, user: UserRef, args: list[str]) -> str:
        if not user.identity_verified:
            return missing_identity_message(user)
        subcommand = args[0]
        if subcommand == "list":
            if len(args) > 2:
                return "用法：/cloudcli run list [数量]"
            limit = self.settings.run_list_limit
            if len(args) == 2:
                limit, error = parse_positive_int(args[1], "数量", 1, 50)
                if error:
                    return error
            return format_run_tasks(
                await self.state.list_run_tasks(user, limit),
                limit,
                self.settings.max_push_text_length,
            )

        if subcommand == "log":
            if len(args) != 2:
                return "用法：/cloudcli run log <任务编号>"
            task, error = await self.state.get_run_task(user, args[1])
            if error:
                return error
            assert task is not None
            return format_run_log(task, self.settings.max_push_text_length)

        if subcommand == "cancel":
            if len(args) != 2:
                return "用法：/cloudcli run cancel <任务编号>"
            task, error = await self.state.get_run_task(user, args[1])
            if error:
                return error
            assert task is not None
            run_id = str(task.get("id") or args[1])
            status = str(task.get("status") or "")
            if status in {"completed", "failed", "cancelled"}:
                return f"任务 #{run_id} 已经是 {status} 状态。"

            local_task = self.run_tasks_by_id.get(run_id)
            abort_message = ""
            session_id = str(task.get("session_id") or "")
            has_session_id = bool(session_id and is_valid_session_id(session_id))
            if local_task and not local_task.done() and not has_session_id:
                self.cancel_requested_run_ids.add(run_id)
                await self.state.update_run_task(
                    run_id,
                    status="cancelling",
                    event="用户请求取消，等待 CloudCLI sessionId 后中止远端任务。",
                )
                return f"已请求取消 CloudCLI 任务 #{run_id}，正在等待 CloudCLI sessionId。"

            if local_task and not local_task.done():
                local_task.cancel()

            if has_session_id:
                abort_message = await self.abort_run_session(
                    {"sessionId": session_id},
                    {"provider": str(task.get("provider") or "")},
                    run_id=run_id,
                )
            await self.state.update_run_task(
                run_id,
                status="cancelled",
                event="用户取消任务。",
                finished=True,
            )
            await self._prune_history()
            return f"已取消 CloudCLI 任务 #{run_id}。{abort_message}"

        return self.request_builder.usage()

    async def _run_agent_background(self, run_id: str, unified_msg_origin: str, payload: dict[str, Any]) -> None:
        text_limit = self.settings.max_push_text_length
        status_interval = self.settings.run_status_interval_seconds
        max_status_pushes = self.settings.max_run_status_pushes
        max_duration = self.settings.agent_max_duration_seconds
        summary_text_limit = max(4000, min(24000, text_limit * 4))
        summary: dict[str, Any] = {
            "sessionId": payload.get("sessionId"),
            "projectPath": payload.get("projectPath"),
            "branch": None,
            "pullRequest": None,
            "assistantText": "",
            "errors": [],
        }
        assistant_text = ""
        assistant_text_truncated = False
        status_pushes = 0
        last_status = ""
        last_status_at = 0.0

        async def finish_as_cancelled(message: str) -> None:
            await self.state.update_run_task(
                run_id,
                status="cancelled",
                event=message,
                finished=True,
            )
            await self._prune_history()
            await self.send_proactive(unified_msg_origin, message)

        async def consume_stream() -> None:
            nonlocal assistant_text
            nonlocal assistant_text_truncated
            nonlocal status_pushes
            nonlocal last_status
            nonlocal last_status_at

            async for event in self.client.stream_agent(payload):
                event_type = str(event.get("type") or event.get("event") or "")
                self.merge_agent_event(summary, event)
                if summary.get("sessionId"):
                    await self.state.update_run_task(run_id, session_id=str(summary["sessionId"]))
                    if run_id in self.cancel_requested_run_ids:
                        message = "用户取消任务。"
                        message += await self.abort_run_session(summary, payload, run_id=run_id)
                        await finish_as_cancelled(message)
                        raise _RunCancelledByUser()

                if event_type in {"done", "complete"}:
                    break

                extracted_text = extract_agent_text(event)
                if extracted_text:
                    if len(assistant_text) < summary_text_limit:
                        remaining = summary_text_limit - len(assistant_text)
                        chunk = extracted_text[:remaining]
                        assistant_text = f"{assistant_text}\n{chunk}" if assistant_text else chunk
                        if len(extracted_text) > remaining:
                            assistant_text_truncated = True
                    else:
                        assistant_text_truncated = True
                    await self.state.update_run_task(
                        run_id,
                        event=f"assistant: {clip_text(extracted_text, 500)}",
                    )

                status_text = format_agent_status(event, text_limit)
                now = asyncio.get_running_loop().time()
                should_push_status = (
                    status_text
                    and status_text != last_status
                    and status_pushes < max_status_pushes
                    and (status_pushes == 0 or now - last_status_at >= status_interval)
                )
                if should_push_status:
                    await self.state.update_run_task(run_id, event=status_text)
                    await self.send_proactive(unified_msg_origin, status_text)
                    status_pushes += 1
                    last_status = status_text
                    last_status_at = now

        try:
            await self.state.update_run_task(run_id, status="running", event="任务已启动。")
            if max_duration > 0:
                await asyncio.wait_for(consume_stream(), timeout=max_duration)
            else:
                await consume_stream()

            if run_id in self.cancel_requested_run_ids:
                message = "用户取消任务。"
                message += await self.abort_run_session(summary, payload, run_id=run_id)
                await finish_as_cancelled(message)
                return

            if assistant_text:
                summary["assistantText"] = assistant_text.strip()
                if assistant_text_truncated:
                    summary["assistantText"] += "\n...[truncated]"
            final_text = format_agent_final(summary, text_limit)
            await self.state.update_run_task(
                run_id,
                status="failed" if summary.get("errors") else "completed",
                event=final_text,
                summary=summary,
                finished=True,
            )
            await self._prune_history()
            await self.send_proactive(unified_msg_origin, final_text)
        except _RunCancelledByUser:
            return
        except asyncio.TimeoutError:
            message = f"CloudCLI 任务超过最大运行时间 {max_duration} 秒，已停止等待。"
            message += await self.abort_run_session(summary, payload, run_id=run_id)
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=message,
                error=message,
                finished=True,
            )
            await self._prune_history()
            await self.send_proactive(unified_msg_origin, message)
        except CloudCLIError as exc:
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=f"CloudCLI 任务失败：{exc}",
                error=str(exc),
                finished=True,
            )
            await self._prune_history()
            await self.send_proactive(unified_msg_origin, f"CloudCLI 任务失败：{exc}")
        except asyncio.CancelledError:
            message = "本地任务已取消。"
            message += await self.abort_run_session(summary, payload, run_id=run_id)
            await self.state.update_run_task(
                run_id,
                status="cancelled",
                event=message,
                finished=True,
            )
            await self._prune_history()
            raise
        except Exception as exc:  # noqa: BLE001
            safe_error = redact_text(str(exc))
            logger.error(
                "CloudCLI agent background task failed:\n%s",
                redact_exception_text(exc),
            )
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=f"CloudCLI 任务异常：{safe_error}",
                error=safe_error,
                finished=True,
            )
            await self._prune_history()
            await self.send_proactive(unified_msg_origin, f"CloudCLI 任务异常：{safe_error}")
        finally:
            self.cancel_requested_run_ids.discard(run_id)
            self.abort_sent_run_ids.discard(run_id)

    async def abort_run_session(
        self,
        summary: dict[str, Any],
        payload: dict[str, Any],
        *,
        run_id: str = "",
    ) -> str:
        session_id = str(summary.get("sessionId") or payload.get("sessionId") or "")
        if not session_id:
            return "\n尚未获得 CloudCLI sessionId，无法主动发送中止请求。"
        if not is_valid_session_id(session_id):
            return "\nCloudCLI sessionId 格式异常，未发送中止请求。"
        if run_id and run_id in self.abort_sent_run_ids:
            return f"\n已向 CloudCLI 发送过中止 session 请求：{session_id}"
        if run_id:
            self.abort_sent_run_ids.add(run_id)
        try:
            await self.client.abort_session(session_id, str(payload.get("provider") or ""))
            return f"\n已向 CloudCLI 发送中止 session 请求：{session_id}"
        except CloudCLIError as exc:
            if run_id:
                self.abort_sent_run_ids.discard(run_id)
            return f"\n尝试中止 CloudCLI session 失败：{exc}"

    def merge_agent_event(self, summary: dict[str, Any], event: dict[str, Any]) -> None:
        event_type = str(event.get("type") or event.get("event") or "")
        if event.get("sessionId"):
            summary["sessionId"] = event.get("sessionId")
        if event.get("projectPath"):
            summary["projectPath"] = event.get("projectPath")

        if event_type == "github-branch":
            summary["branch"] = event.get("branch")
        elif event_type == "github-pr":
            summary["pullRequest"] = event.get("pullRequest")
        elif event_type in {"error", "github-error"}:
            error = event.get("error") or event.get("message") or event
            if isinstance(summary.get("errors"), list):
                summary["errors"].append(error)
        elif event_type == "response":
            data = event.get("data")
            if isinstance(data, dict):
                if data.get("sessionId"):
                    summary["sessionId"] = data["sessionId"]
                if data.get("projectPath"):
                    summary["projectPath"] = data["projectPath"]
                if data.get("branch"):
                    summary["branch"] = data["branch"]
                if data.get("pullRequest"):
                    summary["pullRequest"] = data["pullRequest"]
                if data.get("success") is False and isinstance(summary.get("errors"), list):
                    summary["errors"].append(data.get("error") or data)

    def _on_run_task_done(self, run_id: str, user_key: str) -> None:
        self.run_tasks_by_id.pop(run_id, None)
        self.quota.release(user_key)

    async def _prune_history(self) -> None:
        await self.state.prune_run_history(
            self.settings.max_run_history_per_user,
            self.settings.max_run_history_global,
        )
