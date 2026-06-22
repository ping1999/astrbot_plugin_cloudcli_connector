from __future__ import annotations

from typing import Any

try:
    from ..cloudcli.cloudcli_client import CloudCLIClient, CloudCLIError
    from ..core.config import ConnectorSettings
    from ..persistence.state import PluginState
    from ..persistence.state_models import UserRef, is_valid_session_id
    from ..security.authz import AuthorizationPolicy
    from ..security.run_validation import is_index_session_ref
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_client import CloudCLIClient, CloudCLIError
    from core.config import ConnectorSettings
    from persistence.state import PluginState
    from persistence.state_models import UserRef, is_valid_session_id
    from security.authz import AuthorizationPolicy
    from security.run_validation import is_index_session_ref


class SessionResolver:
    def __init__(
        self,
        *,
        settings: ConnectorSettings,
        authz: AuthorizationPolicy,
        state: PluginState,
        client: CloudCLIClient,
    ) -> None:
        self.settings = settings
        self.authz = authz
        self.state = state
        self.client = client

    async def infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        bindings = await self.state.list_bindings(user)
        if not bindings:
            return "", "当前用户没有绑定 session，请先使用 /cloudcli bind <sessionId>，或显式传入 sessionId。"
        if len(bindings) > 1:
            return "", "当前用户绑定了多个 session，请显式传入 sessionId。"
        return bindings[0], None

    async def resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        resolved, error = await self.state.resolve_session_ref(user, ref)
        if error or resolved is None:
            return resolved, error
        provider = resolved.get("provider") or ""
        if not provider:
            recent = await self.find_recent_session(resolved["id"])
            if recent:
                provider = str(recent.get("provider") or "")
                resolved["provider"] = provider
                resolved["projectPath"] = str(recent.get("projectPath") or "")
                resolved["projectName"] = str(recent.get("projectName") or "")
        return resolved, None

    async def direct_bind_error(self, user: UserRef, ref: str) -> str:
        if is_index_session_ref(ref):
            return ""
        if not is_valid_session_id(ref.strip()):
            return ""
        indexed = await self.state.find_session_index_item(user, ref.strip())
        if indexed:
            return ""
        decision = self.authz.can_bind_direct_session_for_approval(user)
        return "" if decision.allowed else decision.message

    async def direct_session_ref_error(self, user: UserRef, ref: str) -> str:
        if is_index_session_ref(ref):
            return ""
        if not is_valid_session_id(ref.strip()):
            return ""
        return await self.session_usage_error(user, ref.strip())

    async def session_usage_error(self, user: UserRef, session_id: str) -> str:
        if await self.state.has_binding(user, session_id):
            return ""
        if await self.state.find_session_index_item(user, session_id):
            return ""
        decision = self.authz.can_use_direct_session_id(user)
        return "" if decision.allowed else decision.message

    async def find_recent_session(self, session_id: str) -> dict[str, Any] | None:
        try:
            sessions = await self.client.get_recent_sessions(100)
        except CloudCLIError:
            return None
        for item in sessions:
            if item.get("id") == session_id:
                return item
        return None
