"""`/cloudcli run` 请求解析：把聊天参数转换成 CloudCLI Agent API payload。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from ..commands.command_parser import tokenize_command_parts_with_raw_tail
    from ..core.config import ConnectorSettings
    from ..core.constants import RUN_PROVIDERS
    from ..persistence.state_models import UserRef, is_valid_session_id
    from ..security.authz import AuthorizationPolicy
    from ..security.run_validation import (
        has_control_chars,
        is_safe_git_branch_name,
        is_safe_model_name,
        looks_like_github_url,
    )
    from ..sessions.session_resolver import SessionResolver
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from commands.command_parser import tokenize_command_parts_with_raw_tail
    from core.config import ConnectorSettings
    from core.constants import RUN_PROVIDERS
    from persistence.state_models import UserRef, is_valid_session_id
    from security.authz import AuthorizationPolicy
    from security.run_validation import (
        has_control_chars,
        is_safe_git_branch_name,
        is_safe_model_name,
        looks_like_github_url,
    )
    from sessions.session_resolver import SessionResolver


FLAG_OPTIONS = frozenset({"create-branch", "pr", "no-cleanup", "cleanup"})
VALUE_OPTIONS = frozenset({"project", "github", "session", "provider", "model", "branch"})


@dataclass(frozen=True)
class ProjectTarget:
    """本地项目目录目标。"""

    project_path: str

    @property
    def display_target(self) -> str:
        """用于任务列表和启动消息的目标展示文本。"""
        return self.project_path

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        """把目标写入 Agent API payload。"""
        payload["projectPath"] = self.project_path


@dataclass(frozen=True)
class GitHubTarget:
    """GitHub 仓库 URL 目标。"""

    github_url: str

    @property
    def display_target(self) -> str:
        """用于任务列表和启动消息的目标展示文本。"""
        return self.github_url

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        """把目标写入 Agent API payload。"""
        payload["githubUrl"] = self.github_url


@dataclass(frozen=True)
class SessionTarget:
    """已有 CloudCLI session 目标，会带上它关联的项目路径。"""

    session_id: str
    project_path: str
    provider: str = ""

    @property
    def display_target(self) -> str:
        """用于任务列表和启动消息的目标展示文本。"""
        return f"{self.session_id} ({self.project_path})"

    def apply_to_payload(self, payload: dict[str, Any]) -> None:
        """把 session 目标写入 Agent API payload。"""
        payload["sessionId"] = self.session_id
        payload["projectPath"] = self.project_path


RunTarget = ProjectTarget | GitHubTarget | SessionTarget


@dataclass
class ParsedRun:
    """解析成功后的 run 请求。"""

    payload: dict[str, Any]
    display_target: str
    target: RunTarget


@dataclass
class RunOptions:
    """命令行选项的中间结构，先收集再统一校验。"""

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
    """负责解析 run 命令、校验参数、解析目标并生成 Agent API payload。"""

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

    async def parse(
        self,
        user: UserRef,
        args: list[str],
        raw_args: str = "",
    ) -> tuple[ParsedRun | None, str | None]:
        """解析 `/cloudcli run` 参数；成功返回 ParsedRun，失败返回用户可读错误。"""
        if not args:
            return None, self.usage()

        options = RunOptions()
        message_parts: list[str] = []
        message_start_index = -1
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                # `--` 后面的全部内容都视为任务描述，允许用户写以 -- 开头的自然语言。
                message_start_index = index + 1
                message_parts = args[index + 1 :]
                break
            if not token.startswith("--"):
                message_start_index = index
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

        message = _raw_message_from_args(raw_args, message_start_index)
        if message is None:
            message = " ".join(message_parts)
        message = message.strip()
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
        project_decision = self.authz.authorize_project_path(user, project_path)
        if not project_decision.allowed:
            return None, project_decision.message
        if project_decision.path:
            # 权限层会把路径展开成绝对路径，传给 CloudCLI 时使用这个确定值。
            if isinstance(target, ProjectTarget):
                target = ProjectTarget(project_decision.path)
            elif isinstance(target, SessionTarget):
                target = SessionTarget(
                    session_id=target.session_id,
                    project_path=project_decision.path,
                    provider=target.provider,
                )

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
        """返回 run 命令帮助文本。"""
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
        """读取一个 `--name value` 或 `--name=value` 选项。"""
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
        """把单个选项写入 RunOptions；未知选项直接返回帮助错误。"""
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
        """统一校验选项组合和每个值的安全性。"""
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
        """解析任务目标；显式 project/github 优先，否则尝试使用 session。"""
        if options.project_path:
            return ProjectTarget(options.project_path), None
        if options.github_url:
            return GitHubTarget(options.github_url), None

        session_ref = options.session_id
        if not session_ref:
            session_decision = self.authz.can_access_sessions(user)
            if not session_decision.allowed:
                return None, "请通过 --project <path> 或 --github <url> 指定任务目标：" + session_decision.message
            # 省略目标时只允许唯一绑定 session，避免把任务发到错误项目。
            session_ref, error = await self.sessions.infer_single_bound_session(user)
            if error:
                return None, "请通过 --project <path>、--github <url> 或 --session <sessionId> 指定任务目标：" + error

        return await self._resolve_session_target(user, session_ref)

    async def _resolve_session_target(self, user: UserRef, session_ref: str) -> tuple[SessionTarget | None, str | None]:
        """把 session 引用解析为 Agent API 需要的 sessionId、provider 和 projectPath。"""
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
            # Agent API 需要项目路径；旧缓存没有 projectPath 时尝试从最近 session 元数据补齐。
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


def _raw_message_from_args(raw_args: str, message_start_index: int) -> str | None:
    """从原始参数字符串中切出任务描述，保留用户输入的空白、引号和换行感。"""
    if not raw_args or message_start_index < 0:
        return None
    try:
        parts = tokenize_command_parts_with_raw_tail(raw_args)
    except ValueError:
        return None
    if message_start_index >= len(parts):
        return ""
    return raw_args[parts[message_start_index].start :]
