from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import aiohttp

try:
    from .cloudcli_auth import CloudCLIAuth
    from .cloudcli_errors import CloudCLIError
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
    from cloudcli.cloudcli_protocol import (
        MAX_ERROR_BODY_CHARS,
        iter_sse,
        read_response_json_limited,
        read_response_text_limited,
        redact_error_text,
    )


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
        request_payload = dict(payload)
        request_payload["stream"] = True

        timeout = aiohttp.ClientTimeout(
            total=None,
            sock_connect=max(3, self.config.timeout_seconds),
            sock_read=max(10, self.config.agent_idle_timeout_seconds),
        )
        try:
            for attempt in range(2):
                headers = await self.auth.agent_headers()
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        self.api_url("/api/agent"),
                        json=request_payload,
                        headers=headers,
                    ) as response:
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
        return (
            bool(getattr(self.config, "username", ""))
            and bool(getattr(self.config, "password", ""))
        )
