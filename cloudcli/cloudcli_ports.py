"""CloudCLI capabilities consumed by business services.

These protocols keep command, run, session and approval services coupled to the
small API surface they use, while `CloudCLIClient` remains the concrete adapter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

try:
    from .cloudcli_models import AbortSessionResult
    from ..persistence.state_models import PendingApproval
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_models import AbortSessionResult
    from persistence.state_models import PendingApproval


class CloudCLISessionLookupPort(Protocol):
    """Lookup surface needed to resolve session refs into metadata."""

    async def get_recent_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent CloudCLI sessions."""
        ...


class CloudCLIApprovalPort(Protocol):
    """Approval surface used by the approval service."""

    async def get_pending_permissions(self, session_id: str) -> list[PendingApproval]:
        """Return pending permission requests for one session."""
        ...

    async def send_permission_decision(
        self,
        request_id: str,
        allow: bool,
        message: str = "",
        session_id: str = "",
    ) -> None:
        """Send an allow/deny decision for one permission request."""
        ...


class CloudCLIAgentPort(Protocol):
    """Agent task surface used by `/cloudcli run`."""

    async def stream_agent(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Start an agent task and stream events."""
        ...

    async def abort_session(self, session_id: str, provider: str = "") -> AbortSessionResult:
        """Abort the remote session associated with a running task."""
        ...


class CloudCLICommandPort(
    CloudCLISessionLookupPort,
    CloudCLIApprovalPort,
    CloudCLIAgentPort,
    Protocol,
):
    """Full command handler surface, still narrower than the concrete client."""

    async def health_check(self) -> dict[str, Any]:
        """Check CloudCLI auth, REST, WebSocket and agent configuration."""
        ...

    async def get_active_sessions(self) -> dict[str, Any]:
        """Return active CloudCLI sessions."""
        ...

    async def get_session_messages(
        self,
        session_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Return recent messages for one session."""
        ...
