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
    from .approval_service import ApprovalService
    from .authz import AuthorizationPolicy
    from .cloudcli_client import CloudCLIClient, CloudCLIError
    from .command_parser import (
        ParsedCommand,
        parse_command,
        parse_positive_int,
    )
    from .command_router import CommandHandler, CommandRoute, CommandRouter
    from .config import load_connector_settings
    from .constants import PLUGIN_NAME, SESSION_PROVIDERS
    from .formatting import (
        HELP_TEXT,
        clip_text,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
    )
    from .identity import build_user_ref, missing_identity_message
    from .redaction import redact_exception_text, redact_text
    from .run_requests import RunRequestBuilder
    from .run_service import RunService
    from .session_resolver import SessionResolver
    from .state import PluginState, resolve_data_path
    from .state_models import PendingApproval, UserRef, is_valid_session_id
    from .runtime import RunQuota
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from approval_notifications import ApprovalNotificationPolicy
    from approval_service import ApprovalService
    from authz import AuthorizationPolicy
    from cloudcli_client import CloudCLIClient, CloudCLIError
    from command_parser import (
        ParsedCommand,
        parse_command,
        parse_positive_int,
    )
    from command_router import CommandHandler, CommandRoute, CommandRouter
    from config import load_connector_settings
    from constants import PLUGIN_NAME, SESSION_PROVIDERS
    from formatting import (
        HELP_TEXT,
        clip_text,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
    )
    from identity import build_user_ref, missing_identity_message
    from redaction import redact_exception_text, redact_text
    from run_requests import RunRequestBuilder
    from run_service import RunService
    from session_resolver import SessionResolver
    from state import PluginState, resolve_data_path
    from state_models import PendingApproval, UserRef, is_valid_session_id
    from runtime import RunQuota


@register(
    PLUGIN_NAME,
    "Codex",
    "Connect AstrBot commands to CloudCLI sessions and permission approvals.",
    "0.4.0",
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
        self.approval_service = ApprovalService(
            settings=self.settings,
            state=self.state,
            client=self.client,
            notifications=self.approval_notifications,
            send_proactive=self._send_proactive,
            track_task=self._track_task,
        )
        self.run_service = RunService(
            settings=self.settings,
            state=self.state,
            client=self.client,
            request_builder=self.run_request_builder,
            quota=self.run_quota,
            send_proactive=self._send_proactive,
            track_task=self._track_task,
        )
        self.command_router = self._build_command_router()

    async def initialize(self) -> None:
        await self.state.load()
        interrupted = await self.state.mark_interrupted_runs(
            "AstrBot 插件重启，本地后台任务已中断。"
        )
        if interrupted:
            logger.info("Marked %s CloudCLI run task(s) as interrupted.", interrupted)
        await self.approval_service.restore_timeouts()
        self.client.start(auto_connect=self.settings.auto_connect)

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
            logger.error("CloudCLI connector command failed:\n%s", redact_exception_text(exc))
            text = f"CloudCLI 插件处理失败：{redact_text(str(exc))}"
        yield event.plain_result(text)

    async def _dispatch(self, command: ParsedCommand, user: UserRef) -> str:
        return await self.command_router.dispatch(command, user)

    def _build_command_router(self) -> CommandRouter:
        return CommandRouter(
            help_text=HELP_TEXT,
            routes={
                "status": CommandRoute(
                    self._no_args(self._handle_status),
                    usage="用法：/cloudcli status",
                    no_args=True,
                ),
                "session": CommandRoute(
                    self._no_args(self._handle_session),
                    usage="用法：/cloudcli session",
                    no_args=True,
                ),
                "bind": CommandRoute(self._handle_bind),
                "unbind": CommandRoute(self._handle_unbind),
                "chat": CommandRoute(self._handle_chat),
                "run": CommandRoute(self._handle_run),
                "stop": CommandRoute(self._handle_stop),
                "pending": CommandRoute(
                    self._no_args(self._handle_pending),
                    usage="用法：/cloudcli pending",
                    no_args=True,
                ),
                "allow": CommandRoute(self._handle_allow),
                "deny": CommandRoute(self._handle_deny),
                "audit": CommandRoute(self._handle_audit),
                "whoami": CommandRoute(
                    self._no_args(self._handle_whoami),
                    usage="用法：/cloudcli whoami",
                    no_args=True,
                ),
            },
        )

    def _no_args(self, handler) -> CommandHandler:
        async def wrapped(user: UserRef, _args: list[str]) -> str:
            return await handler(user)

        return wrapped

    async def _handle_status(self, user: UserRef) -> str:
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        try:
            return format_health_report(await self.client.health_check())
        except Exception as exc:  # noqa: BLE001
            logger.error("CloudCLI status check failed:\n%s", redact_exception_text(exc))
            return f"检查 CloudCLI 状态失败：{redact_text(str(exc))}"

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

        body = format_session_overview(
            active_payload,
            recent_sessions,
            recent_error,
            self._max_push_text_length(),
        )
        if active_error:
            return f"获取 CloudCLI 活跃 session 失败，以下为最近可绑定 session：{active_error}\n\n{body}"
        return body

    async def _handle_bind(self, user: UserRef, args: list[str]) -> str:
        decision = self.authz.can_bind_sessions(user)
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
            return await self.run_service.handle_run_control(user, args)

        decision = self.authz.can_run_agent(user)
        if not decision.allowed:
            return decision.message
        return await self.run_service.handle_run(user, args)

    async def _handle_pending(self, user: UserRef) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_pending(user)

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
        return await self.approval_service.handle_allow(user, args)

    async def _handle_deny(self, user: UserRef, args: list[str]) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_deny(user, args)

    async def _handle_audit(self, user: UserRef, args: list[str]) -> str:
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_audit(user, args)

    async def _handle_whoami(self, user: UserRef) -> str:
        admin_text = "是" if user.is_admin else "否"
        return f"当前用户标识：{user.user_key}\n昵称：{user.display_name}\nAstrBot 管理员：{admin_text}"

    def _approval_permission_error(self, user: UserRef) -> str:
        decision = self.authz.can_manage_approvals(user)
        return "" if decision.allowed else decision.message

    async def _on_permission_request(self, approval: PendingApproval) -> None:
        await self.approval_service.on_permission_request(approval)

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
                logger.warning(
                    "Failed to push CloudCLI approval to %s: %s",
                    unified_msg_origin,
                    redact_text(str(exc)),
                )
                return
        logger.warning("No platform instance found for %s", unified_msg_origin)

    def _track_task(self, task: asyncio.Task) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _max_push_text_length(self) -> int:
        return self.settings.max_push_text_length
