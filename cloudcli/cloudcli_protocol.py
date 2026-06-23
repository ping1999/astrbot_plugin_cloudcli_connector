from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    from ..core.redaction import redact_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.redaction import redact_text


MAX_ERROR_BODY_CHARS = 2000
MAX_HTTP_RESPONSE_CHARS = 2_000_000
MAX_SSE_EVENT_CHARS = 1_000_000


def build_api_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def build_ws_url(base_url: str, _token: str = "") -> str:
    split = urlsplit(base_url.rstrip("/"))
    scheme = "wss" if split.scheme == "https" else "ws"
    path = f"{split.path.rstrip('/')}/ws"
    return urlunsplit((scheme, split.netloc, path, "", ""))


def build_auth_headers(token: str, api_key: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def is_redirect_status(status: int) -> bool:
    return 300 <= int(status) < 400


def describe_redirect_response(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    location = headers.get("Location", "") if hasattr(headers, "get") else ""
    suffix = f" Location={redact_error_text(str(location))}" if location else ""
    return f"HTTP {getattr(response, 'status', '3xx')} redirect refused{suffix}"


async def read_response_text_limited(
    response: Any,
    max_chars: int = MAX_HTTP_RESPONSE_CHARS,
) -> str:
    max_chars = max(1, int(max_chars))
    max_bytes = max_chars * 4
    body = bytearray()
    async for chunk in response.content.iter_chunked(65536):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > max_bytes:
            raise ValueError("CloudCLI HTTP response body is too large.")
    encoding = getattr(response, "charset", None) or "utf-8"
    text = bytes(body).decode(encoding, errors="replace")
    if len(text) > max_chars:
        raise ValueError("CloudCLI HTTP response body is too large.")
    return text


async def read_response_json_limited(
    response: Any,
    max_chars: int = MAX_HTTP_RESPONSE_CHARS,
) -> Any:
    text = await read_response_text_limited(response, max_chars)
    return json.loads(text) if text else None


async def iter_sse(content: Any) -> AsyncIterator[dict[str, Any]]:
    buffer = ""
    async for chunk in content.iter_any():
        if not chunk:
            continue
        buffer += chunk.decode("utf-8", errors="replace")
        if len(buffer) > MAX_SSE_EVENT_CHARS:
            raise ValueError("CloudCLI agent SSE 单条事件过大，已停止读取。")
        buffer = buffer.replace("\r\n", "\n")
        while "\n\n" in buffer:
            raw_event, buffer = buffer.split("\n\n", 1)
            item = parse_sse_event(raw_event)
            if item is not None:
                yield item
    if buffer.strip():
        item = parse_sse_event(buffer)
        if item is not None:
            yield item


def parse_sse_event(raw_event: str) -> dict[str, Any] | None:
    data_lines: list[str] = []
    event_name = ""
    for line in raw_event.replace("\r\n", "\n").split("\n"):
        if line.startswith("event:"):
            event_name = line.removeprefix("event:").strip()
        elif line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
    if not data_lines:
        return None
    raw_data = "\n".join(data_lines).strip()
    if not raw_data:
        return None
    try:
        parsed = json.loads(raw_data)
    except json.JSONDecodeError:
        parsed = {"content": raw_data}
    if isinstance(parsed, dict):
        if event_name and "event" not in parsed:
            parsed["event"] = event_name
        return parsed
    return {"type": event_name or "message", "data": parsed}


def redact_error_text(value: str) -> str:
    return redact_text(value, MAX_ERROR_BODY_CHARS)
