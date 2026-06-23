"""CloudCLI Agent API 客户端，负责发起流式 agent 任务并解析 SSE 响应。"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import aiohttp

try:
    from .cloudcli_auth import CloudCLIAuth
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_http import create_http_session, raise_for_redirect
    from .cloudcli_protocol import (
        MAX_ERROR_BODY_CHARS,
        iter_sse,
        read_response_json_limited,
        read_response_text_limited,
        redact_error_text,
    )
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_auth import CloudCLIAuth
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_http import create_http_session, raise_for_redirect
    from cloudcli.cloudcli_protocol import (
        MAX_ERROR_BODY_CHARS,
        iter_sse,
        read_response_json_limited,
        read_response_text_limited,
        redact_error_text,
    )


ApiUrl = Callable[[str], str]


class CloudCLIAgentClient:
    """只封装 `/api/agent`，其余 REST/WebSocket 能力由其他客户端负责。"""

    def __init__(
        self,
        *,
        config: Any,
        auth: CloudCLIAuth,
        api_url: ApiUrl,
    ) -> None:
        self.config = config
        self.auth = auth
        self.api_url = api_url

    async def stream_agent(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """发送 agent 任务请求；如果服务端返回 SSE，就逐条 yield 事件。"""
        request_payload = dict(payload)
        request_payload["stream"] = True

        # Agent 任务可能运行很久，因此总超时关闭，只限制连接建立和空闲读取时间。
        timeout = aiohttp.ClientTimeout(
            total=None,
            sock_connect=max(3, self.config.timeout_seconds),
            sock_read=max(10, self.config.agent_idle_timeout_seconds),
        )
        try:
            for attempt in range(2):
                headers = await self.auth.agent_headers()
                async with create_http_session(timeout) as session:
                    async with session.post(
                        self.api_url("/api/agent"),
                        json=request_payload,
                        headers=headers,
                        allow_redirects=False,
                    ) as response:
                        raise_for_redirect(response, "CloudCLI agent API")
                        # JWT 过期时最多刷新一次，避免错误账号/密码导致无限重试。
                        if (
                            response.status == 401
                            and attempt == 0
                            and self._can_refresh_auth()
                        ):
                            await self.auth.clear_cached_token(force=True)
                            continue
                        if response.status >= 400:
                            body = await read_response_text_limited(
                                response,
                                MAX_ERROR_BODY_CHARS,
                            )
                            if response.status == 401 and not self.config.api_key:
                                raise CloudCLIError(
                                    "CloudCLI agent API authentication failed; configure cloudcli_api_key or valid CloudCLI credentials."
                                )
                            raise CloudCLIError(
                                f"CloudCLI agent API request failed: HTTP {response.status} {redact_error_text(body)}"
                            )

                        content_type = response.headers.get("Content-Type", "")
                        if "text/event-stream" not in content_type:
                            # 某些实现可能直接返回 JSON，这里也兼容并包装成一条 response 事件。
                            data = await read_response_json_limited(response)
                            if isinstance(data, dict):
                                yield {"type": "response", "data": data}
                            else:
                                yield {"type": "response", "data": {"raw": data}}
                            return

                        async for item in iter_sse(response.content):
                            yield item
                        return
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(
                f"CloudCLI agent task failed: {redact_error_text(str(exc))}"
            ) from exc

    def _can_refresh_auth(self) -> bool:
        """只有配置用户名密码时才有能力重新登录刷新 JWT。"""
        return (
            bool(getattr(self.config, "username", ""))
            and bool(getattr(self.config, "password", ""))
        )
