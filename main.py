from __future__ import annotations

import asyncio
from typing import Any

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_session import MessageSession

try:
    from .approval_notifications import ApprovalNotificationPolicy
    from .authz import AuthorizationPolicy
    from .cloudcli_client import CloudCLIClient, CloudCLIError
    from .command_parser import (
        ParsedCommand,
        parse_command,
        parse_optional_request_no,
        parse_positive_int,
    )
    from .config import load_connector_settings
    from .constants import MAX_DENY_REASON_LEN, PLUGIN_NAME, SESSION_PROVIDERS
    from .formatting import (
        HELP_TEXT,
        clip_text,
        extract_agent_text,
        format_audit,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_pending,
        format_push_message,
        format_run_log,
        format_run_tasks,
        format_session_overview,
    )
    from .identity import build_user_ref, missing_identity_message
    from .run_requests import RunRequestBuilder
    from .session_resolver import SessionResolver
    from .state import (
        PendingApproval,
        PluginState,
        UserRef,
        is_valid_session_id,
        resolve_data_path,
    )
    from .runtime import RunQuota
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from approval_notifications import ApprovalNotificationPolicy
    from authz import AuthorizationPolicy
    from cloudcli_client import CloudCLIClient, CloudCLIError
    from command_parser import (
        ParsedCommand,
        parse_command,
        parse_optional_request_no,
        parse_positive_int,
    )
    from config import load_connector_settings
    from constants import MAX_DENY_REASON_LEN, PLUGIN_NAME, SESSION_PROVIDERS
    from formatting import (
        HELP_TEXT,
        clip_text,
        extract_agent_text,
        format_audit,
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_pending,
        format_push_message,
        format_run_log,
        format_run_tasks,
        format_session_overview,
    )
    from identity import build_user_ref, missing_identity_message
    from run_requests import RunRequestBuilder
    from session_resolver import SessionResolver
    from state import (
        PendingApproval,
        PluginState,
        UserRef,
        is_valid_session_id,
        resolve_data_path,
    )
    from runtime import RunQuota


@register(
    PLUGIN_NAME,
    "Codex",
    "Connect AstrBot commands to CloudCLI sessions and permission approvals.",
    "0.3.0",
)
class CloudCLIConnectorPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None):
        super().__init__(context)
        self.config = config or {}
        self.settings = load_connector_settings(self.config)
        self.authz = AuthorizationPolicy(self.settings)
        self.approval_notifications = ApprovalNotificationPolicy(
            approval_allowed_user_keys=self.settings.approval_allowed_user_keys,
            approval_require_admin=self.settings.approval_require_admin,
        )
        self.state = PluginState(
            resolve_data_path(__file__, PLUGIN_NAME) / "state.json"
        )
        self.client = CloudCLIClient(
            self.settings.cloudcli,
            on_permission_request=self._on_permission_request,
        )
        self.session_resolver = SessionResolver(
            settings=self.settings,
            authz=self.authz,
            state=self.state,
            client=self.client,
        )
        self.run_request_builder = RunRequestBuilder(
            settings=self.settings,
            authz=self.authz,
            sessions=self.session_resolver,
        )
        self.run_quota = RunQuota(
            self.settings.max_active_runs_per_user,
            self.settings.max_active_runs_global,
        )
        self._background_tasks: set[asyncio.Task] = set()
        self._run_tasks_by_id: dict[str, asyncio.Task] = {}
        self._approval_timeout_tasks: dict[str, asyncio.Task] = {}

    async def initialize(self) -> None:
        await self.state.load()
        if self.settings.auto_connect:
            task = asyncio.create_task(self._warm_connect())
            self._track_task(task)

    async def terminate(self) -> None:
        for task in list(self._background_tasks):
            task.cancel()
        for task in list(self._background_tasks):
            try:
                await task
            except asyncio.CancelledError:
                pass
        await self.client.close()

    @filter.command("cloudcli")
    async def cloudcli(self, event: AstrMessageEvent):
        """CloudCLI session and permission approval commands."""
        user = await build_user_ref(event)
        await self.state.remember_user(user)
        try:
            parsed = parse_command(event.get_message_str() or event.message_str or "")
            text = await self._dispatch(parsed, user)
        except Exception as exc:  # noqa: BLE001
            logger.exception("CloudCLI connector command failed")
            text = f"CloudCLI 插件处理失败：{exc}"
        yield event.plain_result(text)

    async def _dispatch(self, command: ParsedCommand, user: UserRef) -> str:
        if command.name in {"", "help", "-h", "--help"}:
            return HELP_TEXT

        if command.name == "status":
            if command.args:
                return "用法：/cloudcli status"
            return await self._handle_status(user)

        if command.name == "session":
            if command.args:
                return "用法：/cloudcli session"
            return await self._handle_session(user)

        if command.name == "bind":
            return await self._handle_bind(user, command.args)

        if command.name == "unbind":
            return await self._handle_unbind(user, command.args)

        if command.name == "chat":
            return await self._handle_chat(user, command.args)

        if command.name == "run":
            return await self._handle_run(user, command.args)

        if command.name == "stop":
            return await self._handle_stop(user, command.args)

        if command.name == "pending":
            if command.args:
                return "用法：/cloudcli pending"
            return await self._handle_pending(user)

        if command.name == "allow":
            return await self._handle_allow(user, command.args)

        if command.name == "deny":
            return await self._handle_deny(user, command.args)

        if command.name == "audit":
            return await self._handle_audit(user, command.args)

        if command.name == "whoami":
            if command.args:
                return "用法：/cloudcli whoami"
            admin_text = "是" if user.is_admin else "否"
            return f"当前用户标识：{user.user_key}\n昵称：{user.display_name}\nAstrBot 管理员：{admin_text}"

        return f"未知指令：{command.name}\n\n{HELP_TEXT}"

    async def _handle_status(self, user: UserRef) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        try:
            return format_health_report(await self.client.health_check())
        except Exception as exc:  # noqa: BLE001
            logger.exception("CloudCLI status check failed")
            return f"检查 CloudCLI 状态失败：{exc}"

    async def _handle_session(self, user: UserRef) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        active_payload: dict[str, Any] | None = None
        active_error = ""
        recent_sessions: list[dict[str, Any]] = []
        recent_error = ""
        try:
            active_payload = await self.client.get_active_sessions()
        except CloudCLIError as exc:
            active_error = str(exc)

        try:
            recent_sessions = await self.client.get_recent_sessions(
                self.settings.recent_sessions_limit
            )
            await self.state.remember_session_index(
                user,
                recent_sessions,
            )
        except CloudCLIError as exc:
            recent_error = str(exc)

        if active_payload is None and not recent_sessions:
            if active_error and recent_error:
                return (
                    f"获取 CloudCLI 活跃 session 失败：{active_error}\n"
                    f"获取 CloudCLI 最近 session 失败：{recent_error}"
                )
            if active_error:
                return f"获取 CloudCLI 活跃 session 失败：{active_error}"
            if recent_error:
                return f"获取 CloudCLI 最近 session 失败：{recent_error}"

        body = format_session_overview(active_payload, recent_sessions, recent_error)
        if active_error:
            return f"获取 CloudCLI 活跃 session 失败，以下为最近可绑定 session：{active_error}\n\n{body}"
        return body

    async def _handle_bind(self, user: UserRef, args: list[str]) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        if not args:
            return "用法：/cloudcli bind <sessionId|序号|last> 或 /cloudcli bind list"
        if args[0] == "list":
            if len(args) != 1:
                return "用法：/cloudcli bind list"
            return format_bindings(await self.state.list_bindings(user))
        if len(args) != 1:
            return "用法：/cloudcli bind <sessionId|序号|last>"
        direct_error = await self.session_resolver.direct_bind_error(user, args[0])
        if direct_error:
            return direct_error
        resolved, error = await self.session_resolver.resolve_session_ref(user, args[0])
        if error:
            return error
        assert resolved is not None
        session_id = resolved["id"]
        _, message = await self.state.bind_session(user, session_id, self.settings.max_bindings_per_user)
        return message

    async def _handle_unbind(self, user: UserRef, args: list[str]) -> str:
        if not user.identity_verified:
            return missing_identity_message(user)
        if not args:
            return "用法：/cloudcli unbind <sessionId> 或 /cloudcli unbind all"
        if args[0] == "all":
            if len(args) != 1:
                return "用法：/cloudcli unbind all"
            _, message = await self.state.unbind_all(user)
            return message
        if len(args) != 1:
            return "用法：/cloudcli unbind <sessionId>"
        _, message = await self.state.unbind_session(user, args[0].strip())
        return message

    async def _handle_chat(self, user: UserRef, args: list[str]) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        default_limit = self.settings.chat_messages_limit
        session_id = ""
        limit = default_limit

        if not args:
            session_id, error = await self.session_resolver.infer_single_bound_session(user)
            if error:
                return error
        elif len(args) == 1 and args[0].isdigit():
            session_id, error = await self.session_resolver.infer_single_bound_session(user)
            if error:
                return error
            limit, error = parse_positive_int(args[0], "limit", 1, 50)
            if error:
                return error
        elif len(args) in {1, 2}:
            session_id = args[0].strip()
            if not is_valid_session_id(session_id):
                return "sessionId 格式不合法。"
            session_error = await self.session_resolver.session_usage_error(user, session_id)
            if session_error:
                return session_error
            if len(args) == 2:
                limit, error = parse_positive_int(args[1], "limit", 1, 50)
                if error:
                    return error
        else:
            return "用法：/cloudcli chat [sessionId] [limit]"

        try:
            payload = await self.client.get_session_messages(session_id, limit)
            return format_chat_messages(
                session_id,
                payload,
                limit,
                self._max_push_text_length(),
            )
        except CloudCLIError as exc:
            return f"获取 CloudCLI session 消息失败：{exc}"

    async def _handle_run(self, user: UserRef, args: list[str]) -> str:
        if args and args[0] in {"list", "log", "cancel"}:
            return await self._handle_run_control(user, args)

        decision = self.authz.can_run_agent(user)
        if not decision.allowed:
            return decision.message
        parsed, error = await self.run_request_builder.parse(user, args)
        if error:
            return error
        assert parsed is not None

        quota_error = self.run_quota.try_acquire(user.user_key)
        if quota_error:
            return quota_error
        try:
            run_id = await self.state.create_run_task(user, parsed.payload, parsed.display_target)
        except Exception:
            self.run_quota.release(user.user_key)
            raise
        task = asyncio.create_task(
            self._run_agent_background(
                run_id,
                user.unified_msg_origin,
                parsed.payload,
            )
        )
        self._run_tasks_by_id[run_id] = task
        task.add_done_callback(
            lambda _task, task_id=run_id, user_key=user.user_key: self._on_run_task_done(task_id, user_key)
        )
        self._track_task(task)
        return format_agent_start_message(parsed.payload, run_id)

    async def _handle_run_control(self, user: UserRef, args: list[str]) -> str:
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
            return format_run_tasks(await self.state.list_run_tasks(user, limit), limit)

        if subcommand == "log":
            if len(args) != 2:
                return "用法：/cloudcli run log <任务编号>"
            task, error = await self.state.get_run_task(user, args[1])
            if error:
                return error
            assert task is not None
            return format_run_log(task, self._max_push_text_length())

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

            local_task = self._run_tasks_by_id.get(run_id)
            if local_task and not local_task.done():
                local_task.cancel()

            abort_message = ""
            session_id = str(task.get("session_id") or "")
            if session_id and is_valid_session_id(session_id):
                try:
                    await self.client.abort_session(session_id, str(task.get("provider") or ""))
                    abort_message = f"\n已向 CloudCLI 发送中止 session 请求：{session_id}"
                except CloudCLIError as exc:
                    abort_message = f"\n取消了本地任务，但中止 CloudCLI session 失败：{exc}"
            await self.state.update_run_task(
                run_id,
                status="cancelled",
                event="用户取消任务。",
                finished=True,
            )
            return f"已取消 CloudCLI 任务 #{run_id}。{abort_message}"

            return self.run_request_builder.usage()

    async def _handle_pending(self, user: UserRef) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>。"
        sync_error = await self._refresh_pending_for_bindings(bindings)
        approvals = await self.state.visible_pending_for_user(
            user,
            self.settings.max_pending_display,
        )
        body = format_pending(
            approvals,
            self._max_push_text_length(),
        )
        if sync_error:
            return f"同步 CloudCLI 待审批权限失败，以下可能是本地缓存：{sync_error}\n\n{body}"
        return body

    async def _handle_stop(self, user: UserRef, args: list[str]) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        if len(args) not in {1, 2}:
            return "用法：/cloudcli stop <sessionId|序号|last> [provider]"
        direct_error = await self.session_resolver.direct_session_ref_error(user, args[0])
        if direct_error:
            return direct_error
        resolved, error = await self.session_resolver.resolve_session_ref(user, args[0])
        if error:
            return error
        assert resolved is not None
        provider = resolved.get("provider") or ""
        if len(args) == 2:
            provider = args[1].lower().strip()
            if provider not in SESSION_PROVIDERS:
                return f"provider 不支持：{provider}。可选：claude、cursor、codex、gemini、opencode。"
        try:
            await self.client.abort_session(resolved["id"], provider)
            provider_text = f" provider={provider}" if provider else ""
            return f"已向 CloudCLI 发送中止 session 请求：{resolved['id']}{provider_text}"
        except CloudCLIError as exc:
            return f"中止 CloudCLI session 失败：{exc}"

    async def _handle_allow(self, user: UserRef, args: list[str]) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        if len(args) > 1:
            return "用法：/cloudcli allow [序号]"
        request_no, error = parse_optional_request_no(args)
        if error:
            return error
        approval, error = await self._resolve_approval(user, request_no)
        if error:
            return error
        assert approval is not None
        try:
            await self.client.send_permission_decision(approval.request_id, True)
            await self.state.remove_pending(approval.request_id)
            self._cancel_approval_timeout(approval.request_id)
            await self.state.append_audit(
                user=user,
                action="allow",
                approval=approval,
                result="sent",
            )
            return f"已允许：{approval.tool_name} ({approval.session_id})"
        except CloudCLIError as exc:
            await self.state.append_audit(
                user=user,
                action="allow",
                approval=approval,
                result=f"failed: {exc}",
            )
            return f"发送允许决定失败：{exc}"

    async def _handle_deny(self, user: UserRef, args: list[str]) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        if not args:
            return "用法：/cloudcli deny [序号] <原因>"

        request_no: int | None = None
        reason_parts = args
        if args[0].isdigit():
            request_no = int(args[0])
            reason_parts = args[1:]

        reason = " ".join(reason_parts).strip()
        if not reason:
            return "拒绝权限必须填写原因。"
        if len(reason) > MAX_DENY_REASON_LEN:
            return f"拒绝原因太长，请控制在 {MAX_DENY_REASON_LEN} 字以内。"

        approval, error = await self._resolve_approval(user, request_no)
        if error:
            return error
        assert approval is not None
        try:
            await self.client.send_permission_decision(
                approval.request_id,
                False,
                message=reason,
            )
            await self.state.remove_pending(approval.request_id)
            self._cancel_approval_timeout(approval.request_id)
            await self.state.append_audit(
                user=user,
                action="deny",
                approval=approval,
                reason=reason,
                result="sent",
            )
            return f"已拒绝：{approval.tool_name} ({approval.session_id})\n原因：{reason}"
        except CloudCLIError as exc:
            await self.state.append_audit(
                user=user,
                action="deny",
                approval=approval,
                reason=reason,
                result=f"failed: {exc}",
            )
            return f"发送拒绝决定失败：{exc}"

    async def _handle_audit(self, user: UserRef, args: list[str]) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        if len(args) > 1:
            return "用法：/cloudcli audit [数量]"
        limit = 10
        if args:
            limit, error = parse_positive_int(args[0], "数量", 1, 50)
            if error:
                return error
        return format_audit(await self.state.list_audit(user, limit), limit)

    async def _resolve_approval(
        self,
        user: UserRef,
        request_no: int | None,
    ) -> tuple[PendingApproval | None, str | None]:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return None, "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>。"
        await self._refresh_pending_for_bindings(bindings)
        return await self.state.resolve_visible_request(
            user,
            request_no,
            self.settings.max_pending_display,
        )

    def _approval_permission_error(self, user: UserRef) -> str:
        decision = self.authz.can_manage_approvals(user)
        return "" if decision.allowed else decision.message

    def _schedule_approval_timeout(self, approval: PendingApproval) -> None:
        timeout_seconds = self.settings.approval_timeout_seconds
        if timeout_seconds <= 0:
            return
        existing = self._approval_timeout_tasks.get(approval.request_id)
        if existing and not existing.done():
            return
        task = asyncio.create_task(self._approval_timeout_worker(approval.request_id, timeout_seconds))
        self._approval_timeout_tasks[approval.request_id] = task
        task.add_done_callback(
            lambda _task, request_id=approval.request_id: self._approval_timeout_tasks.pop(request_id, None)
        )
        self._track_task(task)

    def _cancel_approval_timeout(self, request_id: str) -> None:
        task = self._approval_timeout_tasks.pop(request_id, None)
        if task and not task.done():
            task.cancel()

    async def _approval_timeout_worker(self, request_id: str, timeout_seconds: int) -> None:
        try:
            await asyncio.sleep(timeout_seconds)
            approval = await self.state.get_pending(request_id)
            if approval is None:
                return
            action = self.settings.approval_timeout_action
            targets = self._approval_detail_targets(
                await self.state.users_bound_to_session(approval.session_id)
            )
            if action == "deny":
                reason = f"审批超时 {timeout_seconds} 秒，自动拒绝。"
                try:
                    await self.client.send_permission_decision(
                        approval.request_id,
                        False,
                        message=reason,
                    )
                    await self.state.remove_pending(approval.request_id)
                    await self.state.append_audit(
                        user=None,
                        action="timeout-deny",
                        approval=approval,
                        reason=reason,
                        result="sent",
                    )
                    text = (
                        "CloudCLI 权限请求已因超时自动拒绝：\n"
                        f"session: {approval.session_id}\n"
                        f"tool: {approval.tool_name}\n"
                        f"reason: {reason}"
                    )
                except CloudCLIError as exc:
                    await self.state.append_audit(
                        user=None,
                        action="timeout-deny",
                        approval=approval,
                        reason=reason,
                        result=f"failed: {exc}",
                    )
                    text = f"CloudCLI 权限请求超时自动拒绝失败：{exc}"
            else:
                text = (
                    "CloudCLI 权限请求仍在等待审批：\n"
                    f"session: {approval.session_id}\n"
                    f"tool: {approval.tool_name}\n"
                    "请使用 /cloudcli pending 查看，然后 /cloudcli allow 或 /cloudcli deny 处理。"
                )

            for target in targets:
                for origin in target.get("origins", []):
                    await self._send_proactive(origin, text)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("CloudCLI approval timeout worker failed: %s", exc)

    async def _refresh_pending_for_bindings(self, bindings: list[str]) -> str:
        async def fetch_one(session_id: str) -> tuple[str, list[PendingApproval], str]:
            try:
                return session_id, await self.client.get_pending_permissions(session_id), ""
            except CloudCLIError as exc:
                return session_id, [], str(exc)

        results = await asyncio.gather(*(fetch_one(session_id) for session_id in bindings))
        errors: list[str] = []
        for session_id, approvals, error in results:
            if error:
                errors.append(f"{session_id}: {error}")
                continue
            removed = await self.state.replace_pending_for_session(session_id, approvals)
            for request_id in removed:
                self._cancel_approval_timeout(request_id)
            for approval in approvals:
                self._schedule_approval_timeout(approval)
        return "; ".join(errors)

    async def _run_agent_background(self, run_id: str, unified_msg_origin: str, payload: dict[str, Any]) -> None:
        text_limit = self._max_push_text_length()
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

        async def consume_stream() -> None:
            nonlocal assistant_text
            nonlocal assistant_text_truncated
            nonlocal status_pushes
            nonlocal last_status
            nonlocal last_status_at

            async for event in self.client.stream_agent(payload):
                event_type = str(event.get("type") or event.get("event") or "")
                self._merge_agent_event(summary, event)
                if summary.get("sessionId"):
                    await self.state.update_run_task(run_id, session_id=str(summary["sessionId"]))

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
                    await self._send_proactive(unified_msg_origin, status_text)
                    status_pushes += 1
                    last_status = status_text
                    last_status_at = now

        try:
            await self.state.update_run_task(run_id, status="running", event="任务已启动。")
            if max_duration > 0:
                await asyncio.wait_for(consume_stream(), timeout=max_duration)
            else:
                await consume_stream()

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
            await self._send_proactive(unified_msg_origin, final_text)
        except asyncio.TimeoutError:
            message = f"CloudCLI 任务超过最大运行时间 {max_duration} 秒，已停止等待。"
            message += await self._abort_run_session(summary, payload)
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=message,
                error=message,
                finished=True,
            )
            await self._send_proactive(unified_msg_origin, message)
        except CloudCLIError as exc:
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=f"CloudCLI 任务失败：{exc}",
                error=str(exc),
                finished=True,
            )
            await self._send_proactive(unified_msg_origin, f"CloudCLI 任务失败：{exc}")
        except asyncio.CancelledError:
            await self.state.update_run_task(
                run_id,
                status="cancelled",
                event="本地任务已取消。",
                finished=True,
            )
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("CloudCLI agent background task failed")
            await self.state.update_run_task(
                run_id,
                status="failed",
                event=f"CloudCLI 任务异常：{exc}",
                error=str(exc),
                finished=True,
            )
            await self._send_proactive(unified_msg_origin, f"CloudCLI 任务异常：{exc}")

    async def _abort_run_session(self, summary: dict[str, Any], payload: dict[str, Any]) -> str:
        session_id = str(summary.get("sessionId") or payload.get("sessionId") or "")
        if not session_id:
            return "\n尚未获得 CloudCLI sessionId，无法主动发送中止请求。"
        if not is_valid_session_id(session_id):
            return "\nCloudCLI sessionId 格式异常，未发送中止请求。"
        try:
            await self.client.abort_session(session_id, str(payload.get("provider") or ""))
            return f"\n已向 CloudCLI 发送中止 session 请求：{session_id}"
        except CloudCLIError as exc:
            return f"\n尝试中止 CloudCLI session 失败：{exc}"

    def _merge_agent_event(self, summary: dict[str, Any], event: dict[str, Any]) -> None:
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

    async def _on_permission_request(self, approval: PendingApproval) -> None:
        await self.state.upsert_pending(approval)
        self._schedule_approval_timeout(approval)
        targets = await self.state.users_bound_to_session(approval.session_id)
        targets = self._approval_detail_targets(targets)
        if not targets:
            return
        text = format_push_message(
            approval,
            self._max_push_text_length(),
        )
        for target in targets:
            for origin in target.get("origins", []):
                await self._send_proactive(origin, text)

    async def _send_proactive(self, unified_msg_origin: str, text: str) -> None:
        try:
            session = MessageSession.from_str(unified_msg_origin)
        except Exception:  # noqa: BLE001
            logger.warning("Invalid unified_msg_origin: %s", unified_msg_origin)
            return

        chain = MessageChain().message(clip_text(text, self._max_push_text_length()))
        for platform in getattr(self.context.platform_manager, "platform_insts", []):
            try:
                meta = platform.meta()
                if meta.id != session.platform_id:
                    continue
                await platform.send_by_session(session, chain)
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to push CloudCLI approval to %s: %s", unified_msg_origin, exc)
                return
        logger.warning("No platform instance found for %s", unified_msg_origin)

    def _approval_detail_targets(self, targets: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
        return self.approval_notifications.plan(targets).detailed_targets

    async def _warm_connect(self) -> None:
        try:
            await self.client.ensure_connected()
        except Exception as exc:  # noqa: BLE001
            logger.warning("CloudCLI auto connect failed: %s", exc)

    def _track_task(self, task: asyncio.Task) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _on_run_task_done(self, run_id: str, user_key: str) -> None:
        self._run_tasks_by_id.pop(run_id, None)
        self.run_quota.release(user_key)

    def _max_push_text_length(self) -> int:
        return self.settings.max_push_text_length
