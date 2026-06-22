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
