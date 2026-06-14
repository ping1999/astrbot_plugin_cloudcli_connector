from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from .config import ConnectorSettings
    from .state import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from config import ConnectorSettings
    from state import UserRef


@dataclass(frozen=True)
class Decision:
    allowed: bool
    message: str = ""


class AuthorizationPolicy:
    def __init__(self, settings: ConnectorSettings) -> None:
        self.settings = settings

    def can_access_sessions(self, user: UserRef) -> Decision:
        if self._is_allowed(
            user,
            allowed_keys=self.settings.session_allowed_user_keys,
            require_admin=self.settings.session_require_admin,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限访问 CloudCLI session。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 session_allowed_user_keys。",
        )

    def can_use_direct_session_id(self, user: UserRef) -> Decision:
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
        if self._is_allowed(
            user,
            allowed_keys=self.settings.run_allowed_user_keys,
            require_admin=self.settings.run_require_admin,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限发起 CloudCLI agent 任务。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 run_allowed_user_keys。",
        )

    def can_manage_approvals(self, user: UserRef) -> Decision:
        if self._is_allowed(
            user,
            allowed_keys=self.settings.approval_allowed_user_keys,
            require_admin=self.settings.approval_require_admin,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限审批 CloudCLI 权限请求。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 approval_allowed_user_keys。",
        )

    def can_manage_approvals_by_values(self, user_key: str, is_admin: bool) -> bool:
        if user_key in self.settings.approval_allowed_user_keys:
            return True
        return bool(is_admin) if self.settings.approval_require_admin else True

    def validate_project_path(self, user: UserRef, project_path: str) -> str:
        if not project_path:
            return ""
        roots = self.settings.allowed_project_roots
        if not roots:
            if user.is_admin or self.settings.allow_unrestricted_project_paths:
                return ""
            return (
                "未配置 allowed_project_roots，非管理员不能使用本地 --project。"
                "请让管理员配置允许的项目根目录，或改用 --github。"
            )

        normalized_project = _normalize_path(project_path)
        for root in roots:
            if _is_path_within(normalized_project, _normalize_path(root)):
                return ""
        return "projectPath 不在 allowed_project_roots 允许的目录内。"

    def _is_allowed(
        self,
        user: UserRef,
        *,
        allowed_keys: frozenset[str],
        require_admin: bool,
    ) -> bool:
        if user.user_key in allowed_keys:
            return True
        return bool(user.is_admin) if require_admin else True


def _normalize_path(value: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(value))
    return os.path.normcase(os.path.abspath(expanded))


def _is_path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False
