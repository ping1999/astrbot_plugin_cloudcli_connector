from __future__ import annotations

import asyncio

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_session import MessageSession

try:
    from .approvals.approval_notifications import ApprovalNotificationPolicy
    from .approvals.approval_service import ApprovalService
    from .cloudcli.cloudcli_client import CloudCLIClient
    from .commands.handlers import CloudCLICommandHandlers
    from .commands.command_parser import (
        ParsedCommand,
        parse_command,
    )
    from .commands.formatting import clip_text
    from .core.config import load_connector_settings
    from .core.constants import PLUGIN_NAME
    from .core.redaction import redact_exception_text, redact_text
    from .persistence.state import PluginState, resolve_data_path
    from .persistence.state_models import PendingApproval, UserRef
    from .runs.run_requests import RunRequestBuilder
    from .runs.run_service import RunService
    from .runs.runtime import RunQuota
    from .security.authz import AuthorizationPolicy
    from .security.identity import build_user_ref
    from .sessions.session_resolver import SessionResolver
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from approvals.approval_notifications import ApprovalNotificationPolicy
    from approvals.approval_service import ApprovalService
    from cloudcli.cloudcli_client import CloudCLIClient
    from commands.handlers import CloudCLICommandHandlers
    from commands.command_parser import (
        ParsedCommand,
        parse_command,
    )
    from commands.formatting import clip_text
    from core.config import load_connector_settings
    from core.constants import PLUGIN_NAME
    from core.redaction import redact_exception_text, redact_text
    from persistence.state import PluginState, resolve_data_path
    from persistence.state_models import PendingApproval, UserRef
    from runs.run_requests import RunRequestBuilder
    from runs.run_service import RunService
    from runs.runtime import RunQuota
    from security.authz import AuthorizationPolicy
    from security.identity import build_user_ref
    from sessions.session_resolver import SessionResolver


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
            approval_access_mode=self.settings.approval_access_mode,
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
        self.command_handlers = CloudCLICommandHandlers(
            settings=self.settings,
            authz=self.authz,
            state=self.state,
            client=self.client,
            session_resolver=self.session_resolver,
            run_service=self.run_service,
            approval_service=self.approval_service,
        )
        self.command_router = self.command_handlers.build_router()

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
