from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from .approval_notifications import ApprovalNotificationPolicy
    from .cloudcli_client import CloudCLIClient, CloudCLIError
    from .command_parser import parse_optional_request_no, parse_positive_int
    from .config import ConnectorSettings
    from .constants import MAX_DENY_REASON_LEN
    from .formatting import format_audit, format_pending, format_push_message
    from .redaction import redact_exception_text
    from .state import PluginState
    from .state_models import PendingApproval, UserRef, pending_storage_key
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from approval_notifications import ApprovalNotificationPolicy
    from cloudcli_client import CloudCLIClient, CloudCLIError
    from command_parser import parse_optional_request_no, parse_positive_int
    from config import ConnectorSettings
    from constants import MAX_DENY_REASON_LEN
    from formatting import format_audit, format_pending, format_push_message
    from redaction import redact_exception_text
    from state import PluginState
    from state_models import PendingApproval, UserRef, pending_storage_key


SendProactive = Callable[[str, str], Awaitable[None]]
TrackTask = Callable[[asyncio.Task], None]
logger = logging.getLogger(__name__)


class ApprovalService:
    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        state: PluginState,
        client: CloudCLIClient,
        notifications: ApprovalNotificationPolicy,
        send_proactive: SendProactive,
        track_task: TrackTask,
    ) -> None:
        self.settings = settings
        self.state = state
        self.client = client
        self.notifications = notifications
        self.send_proactive = send_proactive
        self.track_task = track_task
        self.timeout_tasks: dict[str, asyncio.Task] = {}

    async def restore_timeouts(self) -> None:
        for approval in await self.state.list_pending():
            self.schedule_timeout(approval)

    async def handle_pending(self, user: UserRef) -> str:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>。"
        sync_error = await self.refresh_pending_for_bindings(bindings)
        approvals = await self.state.visible_pending_for_user(
            user,
            self.settings.max_pending_display,
        )
        body = format_pending(
            approvals,
            self.settings.max_push_text_length,
        )
        if sync_error:
            return f"同步 CloudCLI 待审批权限失败，以下可能是本地缓存：{sync_error}\n\n{body}"
        return body

    async def handle_allow(self, user: UserRef, args: list[str]) -> str:
        if len(args) > 1:
            return "用法：/cloudcli allow [序号]"
        request_no, error = parse_optional_request_no(args)
        if error:
            return error
        approval, error = await self._claim_visible_approval(user, request_no, "allow")
        if error:
            return error
        assert approval is not None
        try:
            await self.client.send_permission_decision(
                approval.request_id,
                True,
                session_id=approval.session_id,
            )
            await self.state.remove_pending(approval.session_id, approval.request_id)
            self.cancel_timeout(approval)
            await self.state.append_audit(
                user=user,
                action="allow",
                approval=approval,
                result="sent",
            )
            return f"已允许：{approval.tool_name} ({approval.session_id})"
        except CloudCLIError as exc:
            await self.state.release_pending_claim(approval.session_id, approval.request_id, user.user_key)
            await self.state.append_audit(
                user=user,
                action="allow",
                approval=approval,
                result=f"failed: {exc}",
            )
            return f"发送允许决定失败：{exc}"
        except Exception:
            await self.state.release_pending_claim(approval.session_id, approval.request_id, user.user_key)
            raise

    async def handle_deny(self, user: UserRef, args: list[str]) -> str:
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

        approval, error = await self._claim_visible_approval(user, request_no, "deny")
        if error:
            return error
        assert approval is not None
        try:
            await self.client.send_permission_decision(
                approval.request_id,
                False,
                message=reason,
                session_id=approval.session_id,
            )
            await self.state.remove_pending(approval.session_id, approval.request_id)
            self.cancel_timeout(approval)
            await self.state.append_audit(
                user=user,
                action="deny",
                approval=approval,
                reason=reason,
                result="sent",
            )
            return f"已拒绝：{approval.tool_name} ({approval.session_id})\n原因：{reason}"
        except CloudCLIError as exc:
            await self.state.release_pending_claim(approval.session_id, approval.request_id, user.user_key)
            await self.state.append_audit(
                user=user,
                action="deny",
                approval=approval,
                reason=reason,
                result=f"failed: {exc}",
            )
            return f"发送拒绝决定失败：{exc}"
        except Exception:
            await self.state.release_pending_claim(approval.session_id, approval.request_id, user.user_key)
            raise

    async def handle_audit(self, user: UserRef, args: list[str]) -> str:
        if len(args) > 1:
            return "用法：/cloudcli audit [数量]"
        limit = 10
        if args:
            limit, error = parse_positive_int(args[0], "数量", 1, 50)
            if error:
                return error
        return format_audit(
            await self.state.list_audit(user, limit),
            limit,
            self.settings.max_push_text_length,
        )

    async def on_permission_request(self, approval: PendingApproval) -> None:
        await self.state.upsert_pending(approval)
        self.schedule_timeout(approval)
        targets = self._approval_detail_targets(
            await self.state.users_bound_to_session(approval.session_id)
        )
        if not targets:
            return
        text = format_push_message(
            approval,
            self.settings.max_push_text_length,
        )
        await self._send_to_targets(targets, text)

    def schedule_timeout(self, approval: PendingApproval) -> None:
        timeout_seconds = self.settings.approval_timeout_seconds
        if timeout_seconds <= 0:
            return
        approval_key = pending_storage_key(approval.session_id, approval.request_id)
        if not approval_key:
            return
        existing = self.timeout_tasks.get(approval_key)
        if existing and not existing.done():
            return
        elapsed = max(0.0, time.time() - float(approval.received_at or time.time()))
        delay_seconds = max(0.0, timeout_seconds - elapsed)
        task = asyncio.create_task(
            self._timeout_worker(
                approval.session_id,
                approval.request_id,
                delay_seconds,
                timeout_seconds,
            )
        )
        self.timeout_tasks[approval_key] = task
        task.add_done_callback(
            lambda _task, key=approval_key: self.timeout_tasks.pop(key, None)
        )
        self.track_task(task)

    def cancel_timeout(self, approval: PendingApproval | str) -> None:
        if isinstance(approval, PendingApproval):
            approval_key = pending_storage_key(approval.session_id, approval.request_id)
        else:
            approval_key = approval
        task = self.timeout_tasks.pop(approval_key, None)
        if task and not task.done():
            task.cancel()

    async def refresh_pending_for_bindings(self, bindings: list[str]) -> str:
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
            for approval_key in removed:
                self.cancel_timeout(approval_key)
            for approval in approvals:
                self.schedule_timeout(approval)
        return "; ".join(errors)

    async def _claim_visible_approval(
        self,
        user: UserRef,
        request_no: int | None,
        action: str,
    ) -> tuple[PendingApproval | None, str | None]:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return None, "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>。"
        sync_error = await self.refresh_pending_for_bindings(bindings)
        if sync_error:
            return None, f"同步 CloudCLI 待审批权限失败，未执行审批：{sync_error}"
        return await self.state.claim_visible_request(
            user,
            request_no,
            self.settings.max_pending_display,
            action,
        )

    async def _timeout_worker(
        self,
        session_id: str,
        request_id: str,
        delay_seconds: float,
        timeout_seconds: int,
    ) -> None:
        actor = "system"
        action = self.settings.approval_timeout_action
        try:
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
            claim_action = "timeout-deny" if action == "deny" else "timeout-remind"
            approval, error = await self.state.claim_pending(
                session_id,
                request_id,
                actor=actor,
                action=claim_action,
            )
            if error or approval is None:
                return
            targets = self._approval_detail_targets(
                await self.state.users_bound_to_session(approval.session_id)
            )
            if action == "deny":
                await self._deny_timed_out_approval(approval, timeout_seconds, targets)
                return
            text = (
                "CloudCLI 权限请求仍在等待审批：\n"
                f"session: {approval.session_id}\n"
                f"tool: {approval.tool_name}\n"
                "请使用 /cloudcli pending 查看，然后 /cloudcli allow 或 /cloudcli deny 处理。"
            )
            await self._send_to_targets(targets, text)
            await self.state.release_pending_claim(approval.session_id, approval.request_id, actor)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            approval = await self.state.get_pending(session_id, request_id)
            if approval is not None:
                await self.state.release_pending_claim(approval.session_id, approval.request_id, actor)
            logger.warning(
                "CloudCLI approval timeout worker failed:\n%s",
                redact_exception_text(exc),
            )

    async def _deny_timed_out_approval(
        self,
        approval: PendingApproval,
        timeout_seconds: int,
        targets: tuple[dict[str, Any], ...],
    ) -> None:
        reason = f"审批超时 {timeout_seconds} 秒，自动拒绝。"
        actor = "system"
        try:
            await self.client.send_permission_decision(
                approval.request_id,
                False,
                message=reason,
                session_id=approval.session_id,
            )
            await self.state.remove_pending(approval.session_id, approval.request_id)
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
            await self.state.release_pending_claim(approval.session_id, approval.request_id, actor)
            await self.state.append_audit(
                user=None,
                action="timeout-deny",
                approval=approval,
                reason=reason,
                result=f"failed: {exc}",
            )
            text = f"CloudCLI 权限请求超时自动拒绝失败：{exc}"
        await self._send_to_targets(targets, text)

    async def _send_to_targets(self, targets: tuple[dict[str, Any], ...], text: str) -> None:
        for target in targets:
            for origin in target.get("origins", []):
                await self.send_proactive(origin, text)

    def _approval_detail_targets(self, targets: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
        return self.notifications.plan(targets).detailed_targets
