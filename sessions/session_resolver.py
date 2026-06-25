"""Session 引用解析：把用户输入的 sessionId、序号或 last 转成可用 session 元数据。"""

from __future__ import annotations

from typing import Any

try:
    from ..cloudcli.cloudcli_errors import CloudCLIError
    from ..cloudcli.cloudcli_ports import CloudCLISessionLookupPort
    from ..core.config import ConnectorSettings
    from ..persistence.state import PluginState
    from ..persistence.state_models import UserRef, is_valid_session_id
    from ..security.authz import AuthorizationPolicy
    from ..security.run_validation import is_index_session_ref
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_ports import CloudCLISessionLookupPort
    from core.config import ConnectorSettings
    from persistence.state import PluginState
    from persistence.state_models import UserRef, is_valid_session_id
    from security.authz import AuthorizationPolicy
    from security.run_validation import is_index_session_ref


class SessionResolver:
    """统一处理 session 绑定、序号缓存和直接 sessionId 权限检查。"""

    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        authz: AuthorizationPolicy,
        state: PluginState,
        client: CloudCLISessionLookupPort,
    ) -> None:
        self.settings = settings
        self.authz = authz
        self.state = state
        self.client = client

    async def infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        """当用户没有显式传 sessionId 时，只在恰好绑定一个 session 的情况下自动选择。"""
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "", "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>，或显式传入 sessionId。"
        if len(bindings) > 1:
            return "", "当前用户绑定了多个 session，请显式传入 sessionId。"
        return bindings[0], None

    async def resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        """把 `1`、`last` 或 sessionId 解析为包含 id/provider/projectPath 的字典。"""
        resolved, error = await self.state.resolve_session_ref(
            user,
            ref,
            max_age_seconds=self.settings.session_index_ttl_seconds,
        )
        if error or resolved is None:
            return resolved, error
        provider = resolved.get("provider") or ""
        if not provider:
            # 旧缓存可能只有 sessionId；需要时再从最近 session REST 结果补 provider 和项目路径。
            recent = await self.find_recent_session(resolved["id"])
            if recent:
                provider = str(recent.get("provider") or "")
                resolved["provider"] = provider
                resolved["projectPath"] = str(recent.get("projectPath") or "")
                resolved["projectName"] = str(recent.get("projectName") or "")
        return resolved, None

    async def direct_bind_error(self, user: UserRef, ref: str) -> str:
        """判断绑定命令中的直接 sessionId 是否需要拒绝。"""
        session_decision = self.authz.can_access_sessions(user)
        if is_index_session_ref(ref):
            if session_decision.allowed:
                return ""
            decision = self.authz.can_bind_direct_session_for_approval(user)
            return "" if decision.allowed else decision.message
        if not is_valid_session_id(ref.strip()):
            return ""
        if not session_decision.allowed:
            decision = self.authz.can_bind_direct_session_for_approval(user)
            return "" if decision.allowed else decision.message
        indexed = await self.state.find_session_index_item(
            user,
            ref.strip(),
            max_age_seconds=self.settings.session_index_ttl_seconds,
        )
        if indexed:
            return ""
        decision = self.authz.can_bind_direct_session_for_approval(user)
        return "" if decision.allowed else decision.message

    async def direct_session_ref_error(self, user: UserRef, ref: str) -> str:
        """判断 stop/chat/run 等命令中的直接 sessionId 是否需要拒绝。"""
        if is_index_session_ref(ref):
            return ""
        if not is_valid_session_id(ref.strip()):
            return ""
        return await self.session_usage_error(user, ref.strip())

    async def session_usage_error(self, user: UserRef, session_id: str) -> str:
        """判断用户是否能使用某个 session：已绑定、来自当前序号缓存或具备直连权限。"""
        if await self.state.has_binding(user, session_id):
            return ""
        if await self.state.find_session_index_item(
            user,
            session_id,
            max_age_seconds=self.settings.session_index_ttl_seconds,
        ):
            return ""
        decision = self.authz.can_use_direct_session_id(user)
        return "" if decision.allowed else decision.message

    async def find_recent_session(self, session_id: str) -> dict[str, Any] | None:
        """从 CloudCLI 最近 session 中查找元数据，失败时返回 None 而不打断主流程。"""
        try:
            sessions = await self.client.get_recent_sessions(100)
        except CloudCLIError:
            return None
        for item in sessions:
            if item.get("id") == session_id:
                return item
        return None
