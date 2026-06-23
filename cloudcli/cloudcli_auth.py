"""CloudCLI 认证辅助：管理配置 token、登录获取 token 和鉴权请求头。"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_http import raise_for_redirect
    from .cloudcli_protocol import (
        MAX_HTTP_RESPONSE_CHARS,
        build_auth_headers,
        read_response_text_limited,
        redact_error_text,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_http import raise_for_redirect
    from cloudcli.cloudcli_protocol import (
        MAX_HTTP_RESPONSE_CHARS,
        build_auth_headers,
        read_response_text_limited,
        redact_error_text,
    )


EnsureSession = Callable[[], Awaitable[Any]]
ApiUrl = Callable[[str], str]


class CloudCLIAuth:
    """封装 CloudCLI 的 JWT/API key 组合认证策略。"""

    def __init__(
        self,
        *,
        config: Any,
        ensure_session: EnsureSession,
        api_url: ApiUrl,
    ) -> None:
        """保存配置 token；如果配置了固定 JWT，会优先长期使用它。"""
        self.config = config
        self.ensure_session = ensure_session
        self.api_url = api_url
        self._configured_token = str(getattr(config, "jwt_token", "") or "").strip()
        self._cached_token = self._configured_token

    async def get_token(self, *, allow_anonymous: bool = False) -> str:
        """获取可用 JWT；没有 JWT 时按用户名密码登录，匿名模式允许返回空字符串。"""
        if self._cached_token:
            return self._cached_token
        if not self.config.username or not self.config.password:
            if allow_anonymous:
                return ""
            raise CloudCLIError("未配置 CloudCLI JWT token，也没有配置用户名/密码。")

        return await self._login()

    async def _login(self) -> str:
        """调用 `/api/auth/login` 登录 CloudCLI，并缓存返回的 JWT。"""
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
                allow_redirects=False,
            ) as response:
                # 先拒绝跳转，再读取正文；避免异常服务端用大 body 放大登录失败路径的资源消耗。
                raise_for_redirect(response, "CloudCLI login")
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

    async def clear_cached_token(self, *, force: bool = False) -> None:
        """清除缓存 token；固定配置的 JWT 默认不清除，除非 force=True。"""
        if force or not self._configured_token:
            self._cached_token = ""

    def headers(self, token: str) -> dict[str, str]:
        """生成 Authorization 和 X-API-Key 头。"""
        return build_auth_headers(token, self.config.api_key)

    async def agent_headers(self) -> dict[str, str]:
        """生成 Agent API 头；有 API key 时允许 JWT 登录失败后继续尝试。"""
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
