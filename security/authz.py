"""权限策略：集中决定用户能否查看 session、运行任务、中止任务和处理审批。"""

from __future__ import annotations

from dataclasses import dataclass

try:
    from ..core.config import ConnectorSettings
    from .identity import missing_identity_message
    from .project_paths import ProjectPathDecision, ProjectPathPolicy
    from ..persistence.state_models import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.config import ConnectorSettings
    from persistence.state_models import UserRef
    from security.identity import missing_identity_message
    from security.project_paths import ProjectPathDecision, ProjectPathPolicy


@dataclass(frozen=True)
class Decision:
    """通用授权结果；message 为空表示允许。"""

    allowed: bool
    message: str = ""


class AuthorizationPolicy:
    """把配置中的访问模式、白名单和管理员身份组合成明确授权判断。"""

    def __init__(self, settings: ConnectorSettings) -> None:
        self.settings = settings
        self.project_paths = ProjectPathPolicy(settings)

    def can_access_sessions(self, user: UserRef) -> Decision:
        """判断用户是否能读取 CloudCLI session 列表和聊天记录。"""
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
        """判断用户是否能绑定 session；审批人可绑定自己负责审批的 session。"""
        session_decision = self.can_access_sessions(user)
        if session_decision.allowed:
            return session_decision
        approval_decision = self.can_manage_approvals(user)
        if approval_decision.allowed:
            return Decision(True)
        return session_decision

    def can_bind_direct_session_for_approval(self, user: UserRef) -> Decision:
        """判断审批用户是否允许直接输入原始 sessionId 来绑定。"""
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
        """判断用户能否绕过序号缓存，直接使用未绑定的 sessionId。"""
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
        """判断用户是否能发起新的 CloudCLI agent 任务。"""
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

    def can_stop_sessions(self, user: UserRef) -> Decision:
        """判断用户是否能中止 CloudCLI session。"""
        identity_error = self._identity_error(user)
        if identity_error:
            return Decision(False, identity_error)
        if self._is_allowed(
            user,
            allowed_keys=self.settings.stop_allowed_user_keys,
            access_mode=self.settings.stop_access_mode,
        ):
            return Decision(True)
        return Decision(
            False,
            "当前用户没有权限中止 CloudCLI session。\n"
            f"当前用户标识：{user.user_key}\n"
            "请使用 AstrBot 管理员账号操作，或让管理员把该标识加入 stop_allowed_user_keys。",
        )

    def can_manage_approvals(self, user: UserRef) -> Decision:
        """判断用户是否能查看、允许、拒绝和审计权限请求。"""
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
        """校验本地项目路径是否在允许根目录内。"""
        return self.project_paths.authorize(user, project_path)

    def validate_project_path(self, user: UserRef, project_path: str) -> str:
        """旧调用方使用的便捷接口；返回空字符串表示通过。"""
        return self.project_paths.validate(user, project_path)

    def _is_allowed(
        self,
        user: UserRef,
        *,
        allowed_keys: frozenset[str],
        access_mode: str,
    ) -> bool:
        """按 allowlist、authenticated、admin_or_allowlist 三种模式判断通用权限。"""
        if user.user_key in allowed_keys:
            return True
        if access_mode == "authenticated":
            return True
        if access_mode == "allowlist_only":
            return False
        return bool(user.is_admin)

    def _identity_error(self, user: UserRef) -> str:
        """需要权限边界的操作必须有可靠 sender_id。"""
        if getattr(user, "identity_verified", True):
            return ""
        return missing_identity_message(user)
