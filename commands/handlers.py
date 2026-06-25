"""`/cloudcli` 子命令处理器：做权限检查、参数校验，并调用具体业务服务。"""

from __future__ import annotations

import logging
from typing import Any

try:
    from ..approvals.approval_service import ApprovalService
    from ..cloudcli.cloudcli_errors import CloudCLIError
    from ..cloudcli.cloudcli_ports import CloudCLICommandPort
    from ..core.config import ConnectorSettings
    from ..core.constants import SESSION_PROVIDERS
    from ..core.redaction import redact_exception_text, redact_text
    from ..persistence.state import PluginState
    from ..persistence.state_models import UserRef, is_valid_session_id
    from ..runs.run_service import RunService
    from ..security.authz import AuthorizationPolicy
    from ..security.identity import missing_identity_message
    from ..sessions.session_resolver import SessionResolver
    from .command_parser import ParsedCommand, parse_positive_int
    from .command_router import CommandHandler, CommandRoute, CommandRouter
    from .formatting import (
        HELP_TEXT,
        format_abort_result,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from approvals.approval_service import ApprovalService
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_ports import CloudCLICommandPort
    from commands.command_parser import ParsedCommand, parse_positive_int
    from commands.command_router import CommandHandler, CommandRoute, CommandRouter
    from commands.formatting import (
        HELP_TEXT,
        format_abort_result,
        format_bindings,
        format_chat_messages,
        format_health_report,
        format_session_overview,
    )
    from core.config import ConnectorSettings
    from core.constants import SESSION_PROVIDERS
    from core.redaction import redact_exception_text, redact_text
    from persistence.state import PluginState
    from persistence.state_models import UserRef, is_valid_session_id
    from runs.run_service import RunService
    from security.authz import AuthorizationPolicy
    from security.identity import missing_identity_message
    from sessions.session_resolver import SessionResolver


logger = logging.getLogger(__name__)


class CloudCLICommandHandlers:
    """集中实现所有聊天子命令，保持入口层和业务服务之间的边界清晰。"""

    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        authz: AuthorizationPolicy,
        state: PluginState,
        client: CloudCLICommandPort,
        session_resolver: SessionResolver,
        run_service: RunService,
        approval_service: ApprovalService,
    ) -> None:
        self.settings = settings
        self.authz = authz
        self.state = state
        self.client = client
        self.session_resolver = session_resolver
        self.run_service = run_service
        self.approval_service = approval_service

    def build_router(self) -> CommandRouter:
        """创建命令路由表；简单命令在这里声明是否禁止附加参数。"""
        return CommandRouter(
            help_text=HELP_TEXT,
            routes={
                "status": CommandRoute(
                    self._no_args(self.handle_status),
                    usage="用法：/cloudcli status",
                    no_args=True,
                ),
                "session": CommandRoute(
                    self._no_args(self.handle_session),
                    usage="用法：/cloudcli session",
                    no_args=True,
                ),
                "bind": CommandRoute(self.handle_bind),
                "unbind": CommandRoute(self.handle_unbind),
                "chat": CommandRoute(self.handle_chat),
                "run": CommandRoute(self.handle_run_command, pass_command=True),
                "stop": CommandRoute(self.handle_stop),
                "pending": CommandRoute(
                    self._no_args(self.handle_pending),
                    usage="用法：/cloudcli pending",
                    no_args=True,
                ),
                "allow": CommandRoute(self.handle_allow),
                "deny": CommandRoute(self.handle_deny),
                "audit": CommandRoute(self.handle_audit),
                "whoami": CommandRoute(
                    self._no_args(self.handle_whoami),
                    usage="用法：/cloudcli whoami",
                    no_args=True,
                ),
            },
        )

    def _no_args(self, handler) -> CommandHandler:
        """把无参数 handler 包装成路由统一需要的 `(user, args)` 形式。"""
        async def wrapped(user: UserRef, _args: list[str]) -> str:
            return await handler(user)

        return wrapped

    async def handle_status(self, user: UserRef) -> str:
        """检查 CloudCLI 认证、WebSocket、REST 和 Agent API 的可用性。"""
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        try:
            return format_health_report(await self.client.health_check())
        except Exception as exc:  # noqa: BLE001
            logger.error("CloudCLI status check failed:\n%s", redact_exception_text(exc))
            return f"检查 CloudCLI 状态失败：{redact_text(str(exc))}"

    async def handle_session(self, user: UserRef) -> str:
        """列出活跃 session 和最近可绑定 session，并缓存序号供 `bind 1/last` 使用。"""
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

        # 最近 session 走 REST；即使活跃 session 读取失败，也尽量展示可绑定的历史 session。
        try:
            recent_sessions = await self.client.get_recent_sessions(
                self.settings.recent_sessions_limit
            )
            await self.state.remember_session_index(user, recent_sessions)
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
            self.settings.max_push_text_length,
        )
        if active_error:
            return f"获取 CloudCLI 活跃 session 失败，以下为最近可绑定 session：{active_error}\n\n{body}"
        return body

    async def handle_bind(self, user: UserRef, args: list[str]) -> str:
        """把一个 CloudCLI session 绑定到当前聊天会话，用于后续查看消息和审批通知。"""
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
        # 直接输入 sessionId 比输入序号更敏感，因此先判断当前用户是否允许直连。
        direct_error = await self.session_resolver.direct_bind_error(user, args[0])
        if direct_error:
            return direct_error
        resolved, error = await self.session_resolver.resolve_session_ref(user, args[0])
        if error:
            return error
        assert resolved is not None
        session_id = resolved["id"]
        _, message = await self.state.bind_session(
            user,
            session_id,
            self.settings.max_bindings_per_user,
        )
        return message

    async def handle_unbind(self, user: UserRef, args: list[str]) -> str:
        """解除当前聊天会话上的 session 绑定；同一用户在其他会话的绑定不受影响。"""
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

    async def handle_chat(self, user: UserRef, args: list[str]) -> str:
        """查看指定或唯一绑定 session 的最近消息。"""
        decision = self.authz.can_access_sessions(user)
        if not decision.allowed:
            return decision.message
        default_limit = self.settings.chat_messages_limit
        session_id = ""
        limit = default_limit

        if not args:
            # 没传 sessionId 时只允许用户恰好绑定了一个 session，避免读错会话。
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
                self.settings.max_push_text_length,
            )
        except CloudCLIError as exc:
            return f"获取 CloudCLI session 消息失败：{exc}"

    async def handle_run(self, user: UserRef, args: list[str]) -> str:
        """兼容旧调用路径的 run 入口；新路径使用 `handle_run_command` 保留原始任务文本。"""
        if args and args[0] in {"list", "log", "cancel"}:
            return await self.run_service.handle_run_control(user, args)
        return await self.run_service.handle_run(user, args)

    async def handle_run_command(self, user: UserRef, command: ParsedCommand) -> str:
        """发起或控制 CloudCLI agent 任务，原始参数用于保留任务描述中的空白和引号。"""
        if command.args and command.args[0] in {"list", "log", "cancel"}:
            return await self.run_service.handle_run_control(user, command.args)
        return await self.run_service.handle_run(user, command.args, raw_args=command.raw_args)

    async def handle_pending(self, user: UserRef) -> str:
        """列出当前用户已绑定 session 中可见的待审批权限。"""
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_pending(user)

    async def handle_stop(self, user: UserRef, args: list[str]) -> str:
        """中止一个正在运行的 CloudCLI session。"""
        decision = self.authz.can_stop_sessions(user)
        if not decision.allowed:
            return decision.message
        if len(args) not in {1, 2}:
            return "用法：/cloudcli stop <sessionId|序号|last> [provider]"
        # stop 支持序号引用，也支持受限的直接 sessionId 引用。
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
            result = await self.client.abort_session(resolved["id"], provider)
            return format_abort_result(result, self.settings.max_push_text_length)
        except CloudCLIError as exc:
            return f"中止 CloudCLI session 失败：{exc}"

    async def handle_allow(self, user: UserRef, args: list[str]) -> str:
        """允许一条待审批权限请求。"""
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_allow(user, args)

    async def handle_deny(self, user: UserRef, args: list[str]) -> str:
        """拒绝一条待审批权限请求，拒绝原因会写入审计记录。"""
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_deny(user, args)

    async def handle_audit(self, user: UserRef, args: list[str]) -> str:
        """查看当前聊天会话可见的审批审计记录。"""
        approval_error = self._approval_permission_error(user)
        if approval_error:
            return approval_error
        return await self.approval_service.handle_audit(user, args)

    async def handle_whoami(self, user: UserRef) -> str:
        """展示当前 AstrBot 用户标识，方便管理员复制到白名单配置。"""
        admin_text = "是" if user.is_admin else "否"
        return f"当前用户标识：{user.user_key}\n昵称：{user.display_name}\nAstrBot 管理员：{admin_text}"

    def _approval_permission_error(self, user: UserRef) -> str:
        """返回审批权限错误；空字符串表示允许继续。"""
        decision = self.authz.can_manage_approvals(user)
        return "" if decision.allowed else decision.message
