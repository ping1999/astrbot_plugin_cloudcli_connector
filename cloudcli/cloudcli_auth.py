from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_protocol import (
        MAX_HTTP_RESPONSE_CHARS,
        build_auth_headers,
        read_response_text_limited,
        redact_error_text,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_protocol import (
        MAX_HTTP_RESPONSE_CHARS,
        build_auth_headers,
        read_response_text_limited,
        redact_error_text,
    )


EnsureSession = Callable[[], Awaitable[Any]]
ApiUrl = Callable[[str], str]


class CloudCLIAuth:
    def __init__(
        self,
        *,
        config: Any,
        ensure_session: EnsureSession,
        api_url: ApiUrl,
    ) -> None:
        self.config = config
        self.ensure_session = ensure_session
        self.api_url = api_url
        self._cached_token = str(getattr(config, "jwt_token", "") or "").strip()

    async def get_token(self, *, allow_anonymous: bool = False) -> str:
        if self._cached_token:
            return self._cached_token
        if not self.config.username or not self.config.password:
            if allow_anonymous:
                return ""
            raise CloudCLIError("未配置 CloudCLI JWT token，也没有配置用户名/密码。")

        session = await self.ensure_session()
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        try:
            async with session.post(
                self.api_url("/api/auth/login"),
                json={
                    "username": self.config.username,
                    "password": self.config.password,
                },
                headers=headers,
            ) as response:
                raw_body = await read_response_text_limited(
                    response,
                    MAX_HTTP_RESPONSE_CHARS,
                )
                try:
                    data = json.loads(raw_body) if raw_body else {}
                except json.JSONDecodeError:
                    data = raw_body
                if response.status >= 400:
                    raise CloudCLIError(
                        f"登录 CloudCLI 失败：HTTP {response.status} {redact_error_text(raw_body)}"
                    )
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, CloudCLIError):
                raise
            raise CloudCLIError(f"登录 CloudCLI 失败：{redact_error_text(str(exc))}") from exc

        if not isinstance(data, dict) or not data.get("token"):
            raise CloudCLIError(f"登录 CloudCLI 失败：{redact_error_text(str(data))}")
        self._cached_token = str(data["token"])
        return self._cached_token

    async def clear_cached_token(self) -> None:
        if not self.config.jwt_token.strip():
            self._cached_token = ""

    def headers(self, token: str) -> dict[str, str]:
        return build_auth_headers(token, self.config.api_key)

    async def agent_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        token = ""
        if self._cached_token:
            token = self._cached_token
        elif self.config.username and self.config.password:
            try:
                token = await self.get_token()
            except CloudCLIError:
                if not self.config.api_key:
                    raise
                token = ""
        headers.update(self.headers(token))
        return headers
