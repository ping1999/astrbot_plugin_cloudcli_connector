from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from ..core.config import ConnectorSettings
    from .identity import missing_identity_message
    from ..persistence.state_models import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.config import ConnectorSettings
    from persistence.state_models import UserRef
    from security.identity import missing_identity_message


@dataclass(frozen=True)
class Decision:
    allowed: bool
    message: str = ""


@dataclass(frozen=True)
class ProjectPathDecision:
    allowed: bool
    path: str = ""
    message: str = ""


class AuthorizationPolicy:
    def __init__(self, settings: ConnectorSettings) -> None:
        self.settings = settings

    def can_access_sessions(self, user: UserRef) -> Decision:
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if self._is_allowed(
            user,
            allowed_keys=self.settings.session_allowed_user_keys,
            access_mode=self.settings.session_access_mode,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限访问 CloudCLI session。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 session_allowed_user_keys。",
        )

    def can_bind_sessions(self, user: UserRef) -> Decision:
        session_decision = self.can_access_sessions(user)
        if session_decision.allowed:
            return session_decision
        approval_decision = self.can_manage_approvals(user)
        if approval_decision.allowed:
            return Decision(True)
        return session_decision

    def can_bind_direct_session_for_approval(self, user: UserRef) -> Decision:
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if user.is_admin:
            return Decision(True)
        if self.settings.approval_allow_direct_session_bind:
            approval_decision = self.can_manage_approvals(user)
            if approval_decision.allowed:
                return Decision(True)
        return self.can_use_direct_session_id(user)

    def can_use_direct_session_id(self, user: UserRef) -> Decision:
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if user.is_admin:
            return Decision(True)
        if self.settings.allow_direct_session_id and self.can_access_sessions(user).allowed:
            return Decision(True)
        return Decision(
            False,
            "不能直接使用未绑定的 sessionId。请先执行 /cloudcli session 后使用序号，"
            "或让管理员开启 allow_direct_session_id。",
        )

    def can_run_agent(self, user: UserRef) -> Decision:
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if self._is_allowed(
            user,
            allowed_keys=self.settings.run_allowed_user_keys,
            access_mode=self.settings.run_access_mode,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限发起 CloudCLI agent 任务。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 run_allowed_user_keys。",
        )

    def can_manage_approvals(self, user: UserRef) -> Decision:
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if self._is_allowed(
            user,
            allowed_keys=self.settings.approval_allowed_user_keys,
            access_mode=self.settings.approval_access_mode,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限审批 CloudCLI 权限请求。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 approval_allowed_user_keys。",
        )

    def authorize_project_path(self, user: UserRef, project_path: str) -> ProjectPathDecision:
        if not project_path:
            return ProjectPathDecision(True, "")

        resolved_project = _resolve_path(project_path)
        roots = self.settings.allowed_project_roots
        if not roots:
            if user.is_admin or self.settings.allow_unrestricted_project_paths:
                return ProjectPathDecision(True, resolved_project)
            return ProjectPathDecision(
                False,
                "",
                "未配置 allowed_project_roots，非管理员不能使用本地 --project。"
                "请让管理员配置允许的项目根目录，或改用 --github。"
            )

        normalized_project = _normalize_path(resolved_project)
        for root in roots:
            if _is_path_within(normalized_project, _normalize_path(root)):
                return ProjectPathDecision(True, resolved_project)
        return ProjectPathDecision(False, "", "projectPath 不在 allowed_project_roots 允许的目录内。")

    def validate_project_path(self, user: UserRef, project_path: str) -> str:
        return self.authorize_project_path(user, project_path).message

    def _is_allowed(
        self,
        user: UserRef,
        *,
        allowed_keys: frozenset[str],
        access_mode: str,
    ) -> bool:
        if user.user_key in allowed_keys:
            return True
        if access_mode == "authenticated":
            return True
        if access_mode == "allowlist_only":
            return False
        return bool(user.is_admin)

    def _identity_error(self, user: UserRef) -> str:
        if getattr(user, "identity_verified", True):
            return ""
        return missing_identity_message(user)


def _resolve_path(value: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(value))
    try:
        resolved = Path(expanded).resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = Path(os.path.abspath(expanded))
    return str(resolved)


def _normalize_path(value: str) -> str:
    return os.path.normcase(_resolve_path(value))


def _is_path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False
