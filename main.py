from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass
from typing import Any

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_session import MessageSession

try:
    from .cloudcli_client import CloudCLIClient, CloudCLIConfig, CloudCLIError
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
    from .state import (
        PendingApproval,
        PluginState,
        UserRef,
        is_valid_session_id,
        resolve_data_path,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli_client import CloudCLIClient, CloudCLIConfig, CloudCLIError
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
    from state import (
        PendingApproval,
        PluginState,
        UserRef,
        is_valid_session_id,
        resolve_data_path,
    )


PLUGIN_NAME = "astrbot_plugin_cloudcli_connector"
MAX_DENY_REASON_LEN = 500
MAX_RUN_MESSAGE_LEN = 4000
RUN_PROVIDERS = {"claude", "cursor", "codex", "gemini"}
SESSION_PROVIDERS = RUN_PROVIDERS | {"opencode"}


@dataclass
class ParsedCommand:
    name: str
    args: list[str]
    raw_args: str


@dataclass
class ParsedRun:
    payload: dict[str, Any]
    display_target: str


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
        self.state = PluginState(
            resolve_data_path(__file__, PLUGIN_NAME) / "state.json"
        )
        self.client = CloudCLIClient(
            self._read_cloudcli_config(),
            on_permission_request=self._on_permission_request,
        )
        self._background_tasks: set[asyncio.Task] = set()
        self._run_tasks_by_id: dict[str, asyncio.Task] = {}
        self._approval_timeout_tasks: dict[str, asyncio.Task] = {}

    async def initialize(self) -> None:
        await self.state.load()
        if _read_bool(self.config.get("auto_connect"), True):
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
        user = self._user_ref(event)
        await self.state.remember_user(user)
        try:
            parsed = self._parse_command(event.get_message_str() or event.message_str or "")
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
            return await self._handle_status()

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

    async def _handle_status(self) -> str:
        try:
            return format_health_report(await self.client.health_check())
        except Exception as exc:  # noqa: BLE001
            logger.exception("CloudCLI status check failed")
            return f"检查 CloudCLI 状态失败：{exc}"

    async def _handle_session(self, user: UserRef) -> str:
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
                _read_limited_int(self.config.get("recent_sessions_limit"), 20, 1, 100)
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
        if not args:
            return "用法：/cloudcli bind <sessionId|序号|last> 或 /cloudcli bind list"
        if args[0] == "list":
            if len(args) != 1:
                return "用法：/cloudcli bind list"
            return format_bindings(await self.state.list_bindings(user))
        if len(args) != 1:
            return "用法：/cloudcli bind <sessionId|序号|last>"
        resolved, error = await self._resolve_session_ref(user, args[0])
        if error:
            return error
        assert resolved is not None
        session_id = resolved["id"]
        max_bindings = _read_limited_int(self.config.get("max_bindings_per_user"), 20, 1, 100)
        _, message = await self.state.bind_session(user, session_id, max_bindings)
        return message

    async def _handle_unbind(self, user: UserRef, args: list[str]) -> str:
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
        default_limit = _read_limited_int(self.config.get("chat_messages_limit"), 12, 1, 50)
        session_id = ""
        limit = default_limit

        if not args:
            session_id, error = await self._infer_single_bound_session(user)
            if error:
                return error
        elif len(args) == 1 and args[0].isdigit():
            session_id, error = await self._infer_single_bound_session(user)
            if error:
                return error
            limit, error = _parse_positive_int(args[0], "limit", 1, 50)
            if error:
                return error
        elif len(args) in {1, 2}:
            session_id = args[0].strip()
            if not is_valid_session_id(session_id):
                return "sessionId 格式不合法。"
            if len(args) == 2:
                limit, error = _parse_positive_int(args[1], "limit", 1, 50)
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

        parsed, error = await self._parse_run_args(user, args)
        if error:
            return error
        assert parsed is not None

        run_id = await self.state.create_run_task(user, parsed.payload, parsed.display_target)
        task = asyncio.create_task(
            self._run_agent_background(
                run_id,
                user.unified_msg_origin,
                parsed.payload,
            )
        )
        self._run_tasks_by_id[run_id] = task
        task.add_done_callback(lambda _task, task_id=run_id: self._run_tasks_by_id.pop(task_id, None))
        self._track_task(task)
        return format_agent_start_message(parsed.payload, run_id)

    async def _handle_run_control(self, user: UserRef, args: list[str]) -> str:
        subcommand = args[0]
        if subcommand == "list":
            if len(args) > 2:
                return "用法：/cloudcli run list [数量]"
            limit = _read_limited_int(self.config.get("run_list_limit"), 10, 1, 50)
            if len(args) == 2:
                limit, error = _parse_positive_int(args[1], "数量", 1, 50)
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

        return self._run_usage()

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
            _read_limited_int(self.config.get("max_pending_display"), 30, 1, 100),
        )
        body = format_pending(
            approvals,
            self._max_push_text_length(),
        )
        if sync_error:
            return f"同步 CloudCLI 待审批权限失败，以下可能是本地缓存：{sync_error}\n\n{body}"
        return body

    async def _handle_stop(self, user: UserRef, args: list[str]) -> str:
        if len(args) not in {1, 2}:
            return "用法：/cloudcli stop <sessionId|序号|last> [provider]"
        resolved, error = await self._resolve_session_ref(user, args[0])
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
        request_no, error = self._parse_optional_request_no(args)
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
            limit, error = _parse_positive_int(args[0], "数量", 1, 50)
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
            _read_limited_int(self.config.get("max_pending_display"), 30, 1, 100),
        )

    async def _infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "", "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>，或显式传入 sessionId。"
        if len(bindings) > 1:
            return "", "当前用户绑定了多个 session，请显式传入 sessionId。"
        return bindings[0], None

    async def _resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        resolved, error = await self.state.resolve_session_ref(user, ref)
        if error or resolved is None:
            return resolved, error
        provider = resolved.get("provider") or ""
        if not provider:
            recent = await self._find_recent_session(resolved["id"])
            if recent:
                provider = str(recent.get("provider") or "")
                resolved["provider"] = provider
                resolved["projectPath"] = str(recent.get("projectPath") or "")
                resolved["projectName"] = str(recent.get("projectName") or "")
        return resolved, None

    def _approval_permission_error(self, user: UserRef) -> str:
        if self._can_manage_approvals(user.user_key, user.is_admin):
            return ""
        return (
            "当前用户没有权限审批 CloudCLI 权限请求。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 approval_allowed_user_keys。"
        )

    def _can_manage_approvals(self, user_key: str, is_admin: bool) -> bool:
        allowed = set(_read_str_list(self.config.get("approval_allowed_user_keys")))
        if user_key in allowed:
            return True
        require_admin = _read_bool(self.config.get("approval_require_admin"), True)
        return bool(is_admin) if require_admin else True

    def _schedule_approval_timeout(self, approval: PendingApproval) -> None:
        timeout_seconds = _read_nonnegative_limited_int(self.config.get("approval_timeout_seconds"), 300, 86400)
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
            action = _read_str(self.config.get("approval_timeout_action"), "remind").lower()
            targets = self._filter_approval_targets(
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

    async def _parse_run_args(
        self,
        user: UserRef,
        args: list[str],
    ) -> tuple[ParsedRun | None, str | None]:
        if not args:
            return None, self._run_usage()

        options: dict[str, Any] = {
            "provider": "",
            "projectPath": "",
            "githubUrl": "",
            "sessionId": "",
            "model": "",
            "branchName": "",
            "createBranch": False,
            "createPR": False,
            "cleanup": None,
        }
        message_parts: list[str] = []
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                message_parts = args[index + 1 :]
                break
            if not token.startswith("--"):
                message_parts = args[index:]
                break

            name, value, consumed_next, error = self._read_run_option(args, index)
            if error:
                return None, error
            assert name is not None
            if name == "project":
                options["projectPath"] = value
            elif name == "github":
                options["githubUrl"] = value
            elif name == "session":
                options["sessionId"] = value
            elif name == "provider":
                options["provider"] = value.lower()
            elif name == "model":
                options["model"] = value
            elif name == "branch":
                options["branchName"] = value
            elif name == "create-branch":
                options["createBranch"] = True
            elif name == "pr":
                options["createPR"] = True
                options["createBranch"] = True
            elif name == "no-cleanup":
                options["cleanup"] = False
            elif name == "cleanup":
                options["cleanup"] = True
            else:
                return None, f"未知 run 选项：--{name}\n{self._run_usage()}"
            index += 2 if consumed_next else 1

        message = " ".join(message_parts).strip()
        if not message:
            return None, "任务内容不能为空。\n" + self._run_usage()
        max_message_len = _read_limited_int(
            self.config.get("max_run_message_length"),
            MAX_RUN_MESSAGE_LEN,
            1,
            20000,
        )
        if len(message) > max_message_len:
            return None, f"任务内容太长，请控制在 {max_message_len} 字以内。"

        session_ref = str(options.get("sessionId") or "")
        if session_ref.lower() in {"last", "latest"} or session_ref.isdigit():
            resolved, error = await self._resolve_session_ref(user, session_ref)
            if error:
                return None, error
            assert resolved is not None
            options["sessionId"] = resolved["id"]
            if not options.get("provider") and resolved.get("provider") in RUN_PROVIDERS:
                options["provider"] = resolved["provider"]

        error = self._validate_run_options(options)
        if error:
            return None, error

        error = await self._complete_run_target(user, options)
        if error:
            return None, error

        payload: dict[str, Any] = {
            "message": message,
            "provider": options["provider"] or "claude",
        }
        for key in ("projectPath", "githubUrl", "sessionId", "model", "branchName"):
            if options.get(key):
                payload[key] = options[key]
        if options.get("createBranch"):
            payload["createBranch"] = True
        if options.get("createPR"):
            payload["createPR"] = True
        if options.get("cleanup") is not None:
            payload["cleanup"] = bool(options["cleanup"])

        display_target = payload.get("projectPath") or payload.get("githubUrl") or payload.get("sessionId") or ""
        return ParsedRun(payload=payload, display_target=str(display_target)), None

    def _read_run_option(
        self,
        args: list[str],
        index: int,
    ) -> tuple[str | None, str, bool, str | None]:
        token = args[index]
        raw = token[2:]
        if "=" in raw:
            name, value = raw.split("=", 1)
            if not value:
                return None, "", False, f"--{name} 不能为空。"
            return name, value.strip(), False, None

        name = raw
        flag_options = {"create-branch", "pr", "no-cleanup", "cleanup"}
        value_options = {"project", "github", "session", "provider", "model", "branch"}
        if name in flag_options:
            return name, "", False, None
        if name not in value_options:
            return name, "", False, None
        if index + 1 >= len(args):
            return None, "", False, f"--{name} 缺少参数。"
        value = args[index + 1].strip()
        if not value or value.startswith("--"):
            return None, "", False, f"--{name} 缺少参数。"
        return name, value, True, None

    def _validate_run_options(self, options: dict[str, Any]) -> str | None:
        provider = str(options.get("provider") or "")
        if provider and provider not in RUN_PROVIDERS:
            return f"provider 不支持：{provider}。可选：claude、cursor、codex、gemini。"

        session_id = str(options.get("sessionId") or "")
        if session_id and not is_valid_session_id(session_id):
            return "sessionId 格式不合法。"

        project_path = str(options.get("projectPath") or "")
        if project_path and _has_control_chars(project_path):
            return "projectPath 含有非法控制字符。"

        github_url = str(options.get("githubUrl") or "")
        if github_url and not _looks_like_github_url(github_url):
            return "githubUrl 格式不合法，只支持 github.com 的 HTTPS 或 SSH URL。"

        model = str(options.get("model") or "")
        if model and not _is_safe_short_value(model, 120):
            return "model 格式不合法或过长。"

        branch_name = str(options.get("branchName") or "")
        if branch_name and (len(branch_name) > 120 or _has_control_chars(branch_name)):
            return "branch 名称不合法或过长。"

        target_count = sum(1 for key in ("projectPath", "githubUrl") if options.get(key))
        if target_count > 1:
            return "--project 和 --github 不能同时使用。"
        return None

    async def _complete_run_target(self, user: UserRef, options: dict[str, Any]) -> str | None:
        session_id = str(options.get("sessionId") or "")
        if not session_id and not options.get("projectPath") and not options.get("githubUrl"):
            session_id, error = await self._infer_single_bound_session(user)
            if error:
                return (
                    "请通过 --project <path>、--github <url> 或 --session <sessionId> 指定任务目标；"
                    + error
                )
            options["sessionId"] = session_id

        if options.get("sessionId") and not options.get("projectPath") and not options.get("githubUrl"):
            session_meta = await self._find_recent_session(str(options["sessionId"]))
            if not session_meta:
                return "无法从 CloudCLI 最近 session 中找到该 session 的 projectPath，请改用 --project <path>。"
            project_path = str(session_meta.get("projectPath") or "")
            if not project_path:
                return "该 session 没有关联 projectPath，请改用 --project <path>。"
            options["projectPath"] = project_path
            provider = str(session_meta.get("provider") or "")
            if not options.get("provider") and provider in RUN_PROVIDERS:
                options["provider"] = provider

        if options.get("provider") == "opencode":
            return "/api/agent 当前不支持 opencode，请选择 claude、cursor、codex 或 gemini。"
        if not options.get("projectPath") and not options.get("githubUrl"):
            return "请指定 --project <path> 或 --github <url>。"
        return None

    async def _find_recent_session(self, session_id: str) -> dict[str, Any] | None:
        try:
            sessions = await self.client.get_recent_sessions(
                100
            )
        except CloudCLIError:
            return None
        for item in sessions:
            if item.get("id") == session_id:
                return item
        return None

    def _run_usage(self) -> str:
        return (
            "用法：/cloudcli run [选项] <任务>\n"
            "选项：--project <path>、--github <url>、--session <sessionId>、"
            "--provider <claude|cursor|codex|gemini>、--model <model>、"
            "--branch <name>、--pr、--no-cleanup"
        )

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
        status_interval = _read_limited_int(self.config.get("run_status_interval_seconds"), 20, 1, 3600)
        max_status_pushes = _read_nonnegative_limited_int(self.config.get("max_run_status_pushes"), 10, 50)
        max_duration = _read_nonnegative_limited_int(self.config.get("agent_max_duration_seconds"), 7200, 86400)
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
        targets = await self.state.users_bound_to_session(approval.session_id)
        targets = self._filter_approval_targets(targets)
        if not targets:
            return
        self._schedule_approval_timeout(approval)
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

    def _filter_approval_targets(self, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            target
            for target in targets
            if self._can_manage_approvals(
                str(target.get("user_key") or ""),
                bool(target.get("is_admin")),
            )
        ]

    async def _warm_connect(self) -> None:
        try:
            await self.client.ensure_connected()
        except Exception as exc:  # noqa: BLE001
            logger.warning("CloudCLI auto connect failed: %s", exc)

    def _track_task(self, task: asyncio.Task) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _max_push_text_length(self) -> int:
        return _read_limited_int(self.config.get("max_push_text_length"), 1800, 200, 8000)

    def _read_cloudcli_config(self) -> CloudCLIConfig:
        return CloudCLIConfig(
            base_url=_read_str(self.config.get("cloudcli_base_url"), "http://127.0.0.1:3001"),
            jwt_token=_read_str(self.config.get("cloudcli_jwt_token"), ""),
            username=_read_str(self.config.get("cloudcli_username"), ""),
            password=_read_str(self.config.get("cloudcli_password"), ""),
            api_key=_read_str(self.config.get("cloudcli_api_key"), ""),
            allow_unauthenticated_ws=_read_bool(self.config.get("allow_unauthenticated_ws"), False),
            timeout_seconds=_read_limited_int(self.config.get("request_timeout_seconds"), 8, 2, 120),
            agent_idle_timeout_seconds=_read_limited_int(
                self.config.get("agent_idle_timeout_seconds"),
                120,
                10,
                3600,
            ),
        )

    def _user_ref(self, event: AstrMessageEvent) -> UserRef:
        platform_id = event.get_platform_id() or "unknown-platform"
        sender_id = event.get_sender_id() or event.get_session_id() or event.unified_msg_origin
        display_name = event.get_sender_name() or sender_id
        return UserRef(
            user_key=f"{platform_id}:{sender_id}",
            display_name=display_name,
            unified_msg_origin=event.unified_msg_origin,
            is_admin=_is_event_admin(event),
        )

    def _parse_command(self, message: str) -> ParsedCommand:
        stripped = message.strip()
        if not stripped:
            return ParsedCommand("", [], "")
        try:
            lexer = shlex.shlex(stripped, posix=False)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = [_strip_wrapping_quotes(token) for token in lexer]
        except ValueError:
            return ParsedCommand("help", [], "")
        if tokens and tokens[0].lstrip("/") == "cloudcli":
            tokens = tokens[1:]
        if not tokens:
            return ParsedCommand("help", [], "")
        name = tokens[0].lower()
        args = tokens[1:]
        raw_args = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ""
        return ParsedCommand(name, args, raw_args)

    def _parse_optional_request_no(self, args: list[str]) -> tuple[int | None, str | None]:
        if not args:
            return None, None
        if not args[0].isdigit():
            return None, "序号必须是正整数。"
        value = int(args[0])
        if value < 1:
            return None, "序号必须从 1 开始。"
        return value, None


def _read_str(value: Any, default: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else default


def _read_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _read_nonnegative_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _read_limited_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


def _read_nonnegative_limited_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < 0:
        return 0
    if parsed > maximum:
        return maximum
    return parsed


def _read_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _read_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _parse_positive_int(
    value: str,
    name: str,
    minimum: int,
    maximum: int,
) -> tuple[int, str | None]:
    try:
        parsed = int(value)
    except ValueError:
        return minimum, f"{name} 必须是整数。"
    if parsed < minimum or parsed > maximum:
        return minimum, f"{name} 必须在 {minimum}-{maximum} 之间。"
    return parsed, None


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _looks_like_github_url(value: str) -> bool:
    if _has_control_chars(value) or len(value) > 500:
        return False
    return (
        value.startswith("https://github.com/")
        or value.startswith("git@github.com:")
    )


def _is_safe_short_value(value: str, max_len: int) -> bool:
    if not value or len(value) > max_len or _has_control_chars(value):
        return False
    return not any(char.isspace() for char in value)


def _strip_wrapping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_event_admin(event: AstrMessageEvent) -> bool:
    checker = getattr(event, "is_admin", None)
    if callable(checker):
        try:
            return bool(checker())
        except Exception:  # noqa: BLE001
            pass
    return str(getattr(event, "role", "")).lower() == "admin"
