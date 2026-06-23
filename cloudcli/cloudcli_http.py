from __future__ import annotations

from typing import Any

import aiohttp

try:
    from .cloudcli_errors import CloudCLIError
    from .cloudcli_protocol import describe_redirect_response, is_redirect_status
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_errors import CloudCLIError
    from cloudcli.cloudcli_protocol import describe_redirect_response, is_redirect_status


def create_http_session(timeout: aiohttp.ClientTimeout) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        timeout=timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
    )


def raise_for_redirect(response: Any, context: str) -> None:
    if is_redirect_status(response.status):
        raise CloudCLIError(f"{context} refused redirect: {describe_redirect_response(response)}")
