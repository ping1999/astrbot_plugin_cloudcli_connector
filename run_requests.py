from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from .authz import AuthorizationPolicy
    from .config import ConnectorSettings
    from .constants import RUN_PROVIDERS
    from .run_validation import (
        has_control_chars,
        is_safe_git_branch_name,
        is_safe_short_value,
        looks_like_github_url,
    )
    from .session_resolver import SessionResolver
    from .state import UserRef, is_valid_session_id
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from authz import AuthorizationPolicy
    from config import ConnectorSettings
    from constants import RUN_PROVIDERS
    from run_validation import (
        has_control_chars,
        is_safe_git_branch_name,
        is_safe_short_value,
        looks_like_github_url,
    )
    from session_resolver import SessionResolver
    from state import UserRef, is_valid_session_id


@dataclass
class ParsedRun:
    payload: dict[str, Any]
    display_target: str


class RunRequestBuilder:
    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        authz: AuthorizationPolicy,
        sessions: SessionResolver,
    ) -> None:
        self.settings = settings
        self.authz = authz
        self.sessions = sessions

    async def parse(self, user: UserRef, args: list[str]) -> tuple[ParsedRun | None, str | None]:
        if not args:
            return None, self.usage()

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

            name, value, consumed_next, error = self._read_option(args, index)
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
                return None, f"未知 run 选项：--{name}\n{self.usage()}"
            index += 2 if consumed_next else 1

        message = " ".join(message_parts).strip()
        if not message:
            return None, "任务内容不能为空。\n" + self.usage()
        max_message_len = self.settings.max_run_message_length
        if len(message) > max_message_len:
            return None, f"任务内容太长，请控制在 {max_message_len} 字以内。"

        error = await self._resolve_session_option(user, options)
        if error:
            return None, error

        error = self._validate_options(options)
        if error:
            return None, error

        error = await self._complete_target(user, options)
        if error:
            return None, error
        project_error = self.authz.validate_project_path(user, str(options.get("projectPath") or ""))
        if project_error:
            return None, project_error

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

    def usage(self) -> str:
        return (
            "用法：/cloudcli run [选项] <任务>\n"
            "选项：--project <path>、--github <url>、--session <sessionId>、"
            "--provider <claude|cursor|codex|gemini>、--model <model>、"
            "--branch <name>、--pr、--no-cleanup"
        )

    def _read_option(
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

    async def _resolve_session_option(self, user: UserRef, options: dict[str, Any]) -> str | None:
        session_ref = str(options.get("sessionId") or "")
        if session_ref:
            session_decision = self.authz.can_access_sessions(user)
            if not session_decision.allowed:
                return session_decision.message
        if session_ref.lower() in {"last", "latest"} or session_ref.isdigit():
            resolved, error = await self.sessions.resolve_session_ref(user, session_ref)
            if error:
                return error
            assert resolved is not None
            options["sessionId"] = resolved["id"]
            if not options.get("provider") and resolved.get("provider") in RUN_PROVIDERS:
                options["provider"] = resolved["provider"]
        elif session_ref and is_valid_session_id(session_ref):
            session_error = await self.sessions.session_usage_error(user, session_ref)
            if session_error:
                return session_error
        return None

    def _validate_options(self, options: dict[str, Any]) -> str | None:
        provider = str(options.get("provider") or "")
        if provider and provider not in RUN_PROVIDERS:
            return f"provider 不支持：{provider}。可选：claude、cursor、codex、gemini。"

        session_id = str(options.get("sessionId") or "")
        if session_id and not is_valid_session_id(session_id):
            return "sessionId 格式不合法。"

        project_path = str(options.get("projectPath") or "")
        if project_path and has_control_chars(project_path):
            return "projectPath 含有非法控制字符。"

        github_url = str(options.get("githubUrl") or "")
        if github_url and not looks_like_github_url(github_url):
            return "githubUrl 格式不合法，只支持 github.com 的标准 HTTPS 或 SSH 仓库 URL。"

        model = str(options.get("model") or "")
        if model and not is_safe_short_value(model, 120):
            return "model 格式不合法或过长。"

        branch_name = str(options.get("branchName") or "")
        if branch_name and not is_safe_git_branch_name(branch_name):
            return "branch 名称不合法或过长。"

        target_count = sum(1 for key in ("projectPath", "githubUrl") if options.get(key))
        if target_count > 1:
            return "--project 和 --github 不能同时使用。"
        return None

    async def _complete_target(self, user: UserRef, options: dict[str, Any]) -> str | None:
        session_id = str(options.get("sessionId") or "")
        if not session_id and not options.get("projectPath") and not options.get("githubUrl"):
            session_decision = self.authz.can_access_sessions(user)
            if not session_decision.allowed:
                return "请通过 --project <path> 或 --github <url> 指定任务目标：" + session_decision.message
            session_id, error = await self.sessions.infer_single_bound_session(user)
            if error:
                return "请通过 --project <path>、--github <url> 或 --session <sessionId> 指定任务目标：" + error
            options["sessionId"] = session_id

        if options.get("sessionId") and not options.get("projectPath") and not options.get("githubUrl"):
            session_meta = await self.sessions.find_recent_session(str(options["sessionId"]))
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
