from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import aiohttp

try:
    from .cloudcli_auth import CloudCLIAuth
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_protocol import iter_sse, redact_error_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_auth import CloudCLIAuth
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_protocol import iter_sse, redact_error_text


ApiUrl = Callable[[str], str]


class CloudCLIAgentClient:
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
        headers = await self.auth.agent_headers()
        request_payload = dict(payload)
        request_payload["stream"] = True

        timeout = aiohttp.ClientTimeout(
            total=None,
            sock_connect=max(3, self.config.timeout_seconds),
            sock_read=max(10, self.config.agent_idle_timeout_seconds),
        )
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self.api_url("/api/agent"),
                    json=request_payload,
                    headers=headers,
                ) as response:
                    if response.status >= 400:
                        body = await response.text()
                        if response.status == 401 and not self.config.api_key:
                            raise CloudCLIError(
                                "CloudCLI agent API 认证失败：请在 cloudcli_api_key 填写 CloudCLI UI 生成的 API Key。"
                            )
                        raise CloudCLIError(
                            f"CloudCLI agent API 请求失败：HTTP {response.status} {redact_error_text(body)}"
                        )

                    content_type = response.headers.get("Content-Type", "")
                    if "text/event-stream" not in content_type:
                        data = await response.json(content_type=None)
                        if isinstance(data, dict):
                            yield {"type": "response", "data": data}
                        else:
                            yield {"type": "response", "data": {"raw": data}}
                        return

                    async for item in iter_sse(response.content):
                        yield item
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(
                f"CloudCLI agent 任务执行失败：{redact_error_text(str(exc))}"
            ) from exc
