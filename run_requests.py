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
        is_safe_model_name,
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
        is_safe_model_name,
        looks_like_github_url,
    )
    from session_resolver import SessionResolver
    from state import UserRef, is_valid_session_id


FLAG_OPTIONS = frozenset({"create-branch", "pr", "no-cleanup", "cleanup"})
VALUE_OPTIONS = frozenset({"project", "github", "session", "provider", "model", "branch"})


@dataclass(frozen=True)
class ProjectTarget:
    project_path: str

    @property
    def display_target(self) -> str:
        return self.project_path

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        payload["projectPath"] = self.project_path


@dataclass(frozen=True)
class GitHubTarget:
    github_url: str

    @property
    def display_target(self) -> str:
        return self.github_url

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        payload["githubUrl"] = self.github_url


@dataclass(frozen=True)
class SessionTarget:
    session_id: str
    project_path: str
    provider: str = ""

    @property
    def display_target(self) -> str:
        return f"{self.session_id} ({self.project_path})"

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        payload["sessionId"] = self.session_id
        payload["projectPath"] = self.project_path


RunTarget = ProjectTarget | GitHubTarget | SessionTarget


@dataclass
class ParsedRun:
    payload: dict[str, Any]
    display_target: str
    target: RunTarget


@dataclass
class RunOptions:
    provider: str = ""
    project_path: str = ""
    github_url: str = ""
    session_id: str = ""
    model: str = ""
    branch_name: str = ""
    create_branch: bool = False
    create_pr: bool = False
    cleanup: bool | None = None


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

        options = RunOptions()
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
            error = self._apply_option(options, name, value)
            if error:
                return None, error
            index += 2 if consumed_next else 1

        message = " ".join(message_parts).strip()
        if not message:
            return None, "任务内容不能为空。\n" + self.usage()
        max_message_len = self.settings.max_run_message_length
        if len(message) > max_message_len:
            return None, f"任务内容太长，请控制在 {max_message_len} 字以内。"

        error = self._validate_options(options)
        if error:
            return None, error

        target, error = await self._resolve_target(user, options)
        if error:
            return None, error
        assert target is not None

        project_path = target.project_path if isinstance(target, (ProjectTarget, SessionTarget)) else ""
        project_error = self.authz.validate_project_path(user, project_path)
        if project_error:
            return None, project_error

        provider = options.provider
        if not provider and isinstance(target, SessionTarget):
            provider = target.provider

        payload: dict[str, Any] = {
            "message": message,
            "provider": provider or "claude",
        }
        target.apply_to_payload(payload)
        if options.model:
            payload["model"] = options.model
        if options.branch_name:
            payload["branchName"] = options.branch_name
        if options.create_branch:
            payload["createBranch"] = True
        if options.create_pr:
            payload["createPR"] = True
        if options.cleanup is not None:
            payload["cleanup"] = options.cleanup

        return ParsedRun(
            payload=payload,
            display_target=target.display_target,
            target=target,
        ), None

    def usage(self) -> str:
        return (
            "用法：/cloudcli run [选项] <任务>\n"
            "选项：--project <path>、--github <url>、--session <sessionId>、"
            "--provider <claude|cursor|codex|gemini|opencode>、--model <model>、"
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
            if name in FLAG_OPTIONS:
                return None, "", False, f"--{name} 不接受参数。"
            if not value:
                return None, "", False, f"--{name} 不能为空。"
            return name, value.strip(), False, None

        name = raw
        if name in FLAG_OPTIONS:
            return name, "", False, None
        if name not in VALUE_OPTIONS:
            return name, "", False, None
        if index + 1 >= len(args):
            return None, "", False, f"--{name} 缺少参数。"
        value = args[index + 1].strip()
        if not value or value.startswith("--"):
            return None, "", False, f"--{name} 缺少参数。"
        return name, value, True, None

    def _apply_option(self, options: RunOptions, name: str, value: str) -> str | None:
        if name == "project":
            options.project_path = value
        elif name == "github":
            options.github_url = value
        elif name == "session":
            options.session_id = value
        elif name == "provider":
            options.provider = value.lower()
        elif name == "model":
            options.model = value
        elif name == "branch":
            options.branch_name = value
        elif name == "create-branch":
            options.create_branch = True
        elif name == "pr":
            options.create_pr = True
            options.create_branch = True
        elif name == "no-cleanup":
            options.cleanup = False
        elif name == "cleanup":
            options.cleanup = True
        else:
            return f"未知 run 选项：--{name}\n{self.usage()}"
        return None

    def _validate_options(self, options: RunOptions) -> str | None:
        provider = options.provider
        if provider and provider not in RUN_PROVIDERS:
            return f"provider 不支持：{provider}。可选：claude、cursor、codex、gemini、opencode。"

        session_id = options.session_id
        if session_id and not (
            session_id.lower() in {"last", "latest"}
            or session_id.isdigit()
            or is_valid_session_id(session_id)
        ):
            return "sessionId 格式不合法。"

        if options.project_path and has_control_chars(options.project_path):
            return "projectPath 含有非法控制字符。"

        if options.github_url and not looks_like_github_url(options.github_url):
            return "githubUrl 格式不合法，只支持 github.com 的标准 HTTPS 或 SSH 仓库 URL。"

        if options.model and not is_safe_model_name(options.model):
            return "model 格式不合法或过长。"

        if options.branch_name and not is_safe_git_branch_name(options.branch_name):
            return "branch 名称不合法或过长。"

        target_count = sum(
            1
            for value in (options.project_path, options.github_url, options.session_id)
            if value
        )
        if target_count > 1:
            return "--project、--github 和 --session 不能同时使用。"
        return None

    async def _resolve_target(self, user: UserRef, options: RunOptions) -> tuple[RunTarget | None, str | None]:
        if options.project_path:
            return ProjectTarget(options.project_path), None
        if options.github_url:
            return GitHubTarget(options.github_url), None

        session_ref = options.session_id
        if not session_ref:
            session_decision = self.authz.can_access_sessions(user)
            if not session_decision.allowed:
                return None, "请通过 --project <path> 或 --github <url> 指定任务目标：" + session_decision.message
            session_ref, error = await self.sessions.infer_single_bound_session(user)
            if error:
                return None, "请通过 --project <path>、--github <url> 或 --session <sessionId> 指定任务目标：" + error

        return await self._resolve_session_target(user, session_ref)

    async def _resolve_session_target(self, user: UserRef, session_ref: str) -> tuple[SessionTarget | None, str | None]:
        session_decision = self.authz.can_access_sessions(user)
        if not session_decision.allowed:
            return None, session_decision.message

        if session_ref.lower() in {"last", "latest"} or session_ref.isdigit():
            resolved, error = await self.sessions.resolve_session_ref(user, session_ref)
            if error:
                return None, error
            assert resolved is not None
        else:
            if not is_valid_session_id(session_ref):
                return None, "sessionId 格式不合法。"
            session_error = await self.sessions.session_usage_error(user, session_ref)
            if session_error:
                return None, session_error
            resolved = {"id": session_ref, "provider": ""}

        session_id = str(resolved.get("id") or "")
        if not is_valid_session_id(session_id):
            return None, "sessionId 格式不合法。"

        provider = str(resolved.get("provider") or "")
        project_path = str(resolved.get("projectPath") or "")
        if not project_path:
            session_meta = await self.sessions.find_recent_session(session_id)
            if not session_meta:
                return None, "无法从 CloudCLI 最近 session 中找到该 session 的 projectPath，请改用 --project <path>。"
            project_path = str(session_meta.get("projectPath") or "")
            if not provider:
                provider = str(session_meta.get("provider") or "")
        if not project_path:
            return None, "该 session 没有关联 projectPath，请改用 --project <path>。"
        if provider not in RUN_PROVIDERS:
            provider = ""
        return SessionTarget(session_id=session_id, project_path=project_path, provider=provider), None
