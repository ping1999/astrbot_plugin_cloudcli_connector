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
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_bindings,
        format_chat_messages,
        format_pending,
        format_push_message,
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
        format_agent_final,
        format_agent_start_message,
        format_agent_status,
        format_bindings,
        format_chat_messages,
        format_pending,
        format_push_message,
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
    "0.2.0",
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

        if command.name == "session":
            if command.args:
                return "用法：/cloudcli session"
            return await self._handle_session()

        if command.name == "bind":
            return await self._handle_bind(user, command.args)

        if command.name == "unbind":
            return await self._handle_unbind(user, command.args)

        if command.name == "chat":
            return await self._handle_chat(user, command.args)

        if command.name == "run":
            return await self._handle_run(user, command.args)

        if command.name == "pending":
            if command.args:
                return "用法：/cloudcli pending"
            return await self._handle_pending(user)

        if command.name == "allow":
            return await self._handle_allow(user, command.args)

        if command.name == "deny":
            return await self._handle_deny(user, command.args)

        return f"未知指令：{command.name}\n\n{HELP_TEXT}"

    async def _handle_session(self) -> str:
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
                _read_int(self.config.get("recent_sessions_limit"), 20)
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
            return "用法：/cloudcli bind <sessionId> 或 /cloudcli bind list"
        if args[0] == "list":
            if len(args) != 1:
                return "用法：/cloudcli bind list"
            return format_bindings(await self.state.list_bindings(user))
        if len(args) != 1:
            return "用法：/cloudcli bind <sessionId>"
        session_id = args[0].strip()
        if not is_valid_session_id(session_id):
            return "sessionId 格式不合法，只允许字母、数字、点、下划线、冒号和短横线。"
        max_bindings = _read_int(self.config.get("max_bindings_per_user"), 20)
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
        default_limit = _read_int(self.config.get("chat_messages_limit"), 12)
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
                _read_int(self.config.get("max_push_text_length"), 1800),
            )
        except CloudCLIError as exc:
            return f"获取 CloudCLI session 消息失败：{exc}"

    async def _handle_run(self, user: UserRef, args: list[str]) -> str:
        parsed, error = await self._parse_run_args(user, args)
        if error:
            return error
        assert parsed is not None

        task = asyncio.create_task(
            self._run_agent_background(
                user.unified_msg_origin,
                parsed.payload,
            )
        )
        self._track_task(task)
        return format_agent_start_message(parsed.payload)

    async def _handle_pending(self, user: UserRef) -> str:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>。"
        sync_error = await self._refresh_pending_for_bindings(bindings)
        approvals = await self.state.visible_pending_for_user(
            user,
            _read_int(self.config.get("max_pending_display"), 30),
        )
        body = format_pending(
            approvals,
            _read_int(self.config.get("max_push_text_length"), 1800),
        )
        if sync_error:
            return f"同步 CloudCLI 待审批权限失败，以下可能是本地缓存：{sync_error}\n\n{body}"
        return body

    async def _handle_allow(self, user: UserRef, args: list[str]) -> str:
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
            return f"已允许：{approval.tool_name} ({approval.session_id})"
        except CloudCLIError as exc:
            return f"发送允许决定失败：{exc}"

    async def _handle_deny(self, user: UserRef, args: list[str]) -> str:
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
            return f"已拒绝：{approval.tool_name} ({approval.session_id})\n原因：{reason}"
        except CloudCLIError as exc:
            return f"发送拒绝决定失败：{exc}"

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
            _read_int(self.config.get("max_pending_display"), 30),
        )

    async def _infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "", "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>，或显式传入 sessionId。"
        if len(bindings) > 1:
            return "", "当前用户绑定了多个 session，请显式传入 sessionId。"
        return bindings[0], None

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
        max_message_len = _read_int(self.config.get("max_run_message_length"), MAX_RUN_MESSAGE_LEN)
        if len(message) > max_message_len:
            return None, f"任务内容太长，请控制在 {max_message_len} 字以内。"

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
                max(100, _read_int(self.config.get("recent_sessions_limit"), 20))
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
        approvals_to_merge: list[PendingApproval] = []
        errors: list[str] = []
        for session_id, approvals, error in results:
            approvals_to_merge.extend(approvals)
            if error:
                errors.append(f"{session_id}: {error}")
        if approvals_to_merge:
            await self.state.merge_pending(approvals_to_merge)
        return "; ".join(errors)

    async def _run_agent_background(self, unified_msg_origin: str, payload: dict[str, Any]) -> None:
        text_limit = _read_int(self.config.get("max_push_text_length"), 1800)
        status_interval = _read_int(self.config.get("run_status_interval_seconds"), 20)
        max_status_pushes = _read_int(self.config.get("max_run_status_pushes"), 10)
        summary: dict[str, Any] = {
            "sessionId": payload.get("sessionId"),
            "projectPath": payload.get("projectPath"),
            "branch": None,
            "pullRequest": None,
            "assistantText": "",
            "errors": [],
        }
        text_parts: list[str] = []
        status_pushes = 0
        last_status = ""
        last_status_at = 0.0

        try:
            async for event in self.client.stream_agent(payload):
                event_type = str(event.get("type") or event.get("event") or "")
                self._merge_agent_event(summary, event)

                if event_type in {"done", "complete"}:
                    break

                extracted_text = extract_agent_text(event)
                if extracted_text:
                    text_parts.append(extracted_text)

                status_text = format_agent_status(event, text_limit)
                now = asyncio.get_running_loop().time()
                should_push_status = (
                    status_text
                    and status_text != last_status
                    and status_pushes < max_status_pushes
                    and (status_pushes == 0 or now - last_status_at >= status_interval)
                )
                if should_push_status:
                    await self._send_proactive(unified_msg_origin, status_text)
                    status_pushes += 1
                    last_status = status_text
                    last_status_at = now

            if text_parts:
                summary["assistantText"] = "\n".join(text_parts).strip()
            await self._send_proactive(unified_msg_origin, format_agent_final(summary, text_limit))
        except CloudCLIError as exc:
            await self._send_proactive(unified_msg_origin, f"CloudCLI 任务失败：{exc}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("CloudCLI agent background task failed")
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
        if not targets:
            return
        text = format_push_message(
            approval,
            _read_int(self.config.get("max_push_text_length"), 1800),
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

        chain = MessageChain().message(clip_text(text, _read_int(self.config.get("max_push_text_length"), 1800)))
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

    async def _warm_connect(self) -> None:
        try:
            await self.client.ensure_connected()
        except Exception as exc:  # noqa: BLE001
            logger.warning("CloudCLI auto connect failed: %s", exc)

    def _track_task(self, task: asyncio.Task) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _read_cloudcli_config(self) -> CloudCLIConfig:
        return CloudCLIConfig(
            base_url=_read_str(self.config.get("cloudcli_base_url"), "http://127.0.0.1:3001"),
            jwt_token=_read_str(self.config.get("cloudcli_jwt_token"), ""),
            username=_read_str(self.config.get("cloudcli_username"), ""),
            password=_read_str(self.config.get("cloudcli_password"), ""),
            api_key=_read_str(self.config.get("cloudcli_api_key"), ""),
            allow_unauthenticated_ws=_read_bool(self.config.get("allow_unauthenticated_ws"), False),
            timeout_seconds=_read_int(self.config.get("request_timeout_seconds"), 8),
        )

    def _user_ref(self, event: AstrMessageEvent) -> UserRef:
        platform_id = event.get_platform_id() or "unknown-platform"
        sender_id = event.get_sender_id() or event.get_session_id() or event.unified_msg_origin
        display_name = event.get_sender_name() or sender_id
        return UserRef(
            user_key=f"{platform_id}:{sender_id}",
            display_name=display_name,
            unified_msg_origin=event.unified_msg_origin,
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


def _read_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


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
        or value.startswith("http://github.com/")
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
