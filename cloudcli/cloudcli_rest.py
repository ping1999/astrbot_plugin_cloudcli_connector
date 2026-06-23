from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

try:
    from .cloudcli_auth import CloudCLIAuth
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_http import raise_for_redirect
    from .cloudcli_models import extract_recent_sessions
    from .cloudcli_protocol import (
        MAX_ERROR_BODY_CHARS,
        read_response_json_limited,
        read_response_text_limited,
        redact_error_text,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_auth import CloudCLIAuth
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_http import raise_for_redirect
    from cloudcli.cloudcli_models import extract_recent_sessions
    from cloudcli.cloudcli_protocol import (
        MAX_ERROR_BODY_CHARS,
        read_response_json_limited,
        read_response_text_limited,
        redact_error_text,
    )


EnsureSession = Callable[[], Awaitable[Any]]
ApiUrl = Callable[[str], str]


class CloudCLIRestClient:
    def __init__(
        self,
        *,
        config: Any,
        auth: CloudCLIAuth,
        ensure_session: EnsureSession,
        api_url: ApiUrl,
    ) -> None:
        self.config = config
        self.auth = auth
        self.ensure_session = ensure_session
        self.api_url = api_url

    async def get_recent_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        token = await self.auth.get_token()
        headers = self.auth.headers(token)
        params = {
            "skipSynchronization": "false",
            "sessionsLimit": str(max(1, min(limit, 100))),
            "sessionsOffset": "0",
        }
        try:
            data = await self._get_json_with_auth_retry("/api/projects", params, headers)
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(f"读取 CloudCLI 最近 session 失败：{exc}") from exc

        try:
            return extract_recent_sessions(data, limit)
        except ValueError as exc:
            raise CloudCLIError(str(exc)) from exc

    async def get_session_messages(
        self,
        session_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        token = await self.auth.get_token()
        params: dict[str, str] = {}
        if limit >= 0:
            params["limit"] = str(max(0, min(limit, 100)))
            params["offset"] = str(max(0, offset))
        path = f"/api/providers/sessions/{quote(session_id, safe='')}/messages"
        try:
            data = await self._get_json_with_auth_retry(path, params, self.auth.headers(token))
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(f"读取 CloudCLI session 消息失败：{exc}") from exc

        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {
                "messages": data,
                "total": len(data),
                "hasMore": False,
                "offset": 0,
                "limit": len(data),
            }
        raise CloudCLIError("无法解析 CloudCLI session 消息响应。")

    async def _get_json_with_auth_retry(
        self,
        path: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> Any:
        data, unauthorized = await self._get_json(path, params, headers)
        if not unauthorized:
            return data
        if not (self.config.username and self.config.password):
            raise CloudCLIError("CloudCLI REST 认证失败，请检查 JWT token 或用户名/密码。")

        await self.auth.clear_cached_token(force=True)
        token = await self.auth.get_token()
        data, unauthorized = await self._get_json(path, params, self.auth.headers(token))
        if unauthorized:
            raise CloudCLIError("CloudCLI REST 认证失败，请检查用户名/密码。")
        return data

    async def _get_json(
        self,
        path: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> tuple[Any, bool]:
        session = await self.ensure_session()
        async with session.get(
            self.api_url(path),
            params=params,
            headers=headers,
            allow_redirects=False,
        ) as response:
            raise_for_redirect(response, "CloudCLI REST request")
            if response.status == 401:
                return None, True
            if response.status >= 400:
                body = await read_response_text_limited(response, MAX_ERROR_BODY_CHARS)
                raise CloudCLIError(
                    f"CloudCLI REST 请求失败：HTTP {response.status} {redact_error_text(body)}"
                )
            return await read_response_json_limited(response), False
