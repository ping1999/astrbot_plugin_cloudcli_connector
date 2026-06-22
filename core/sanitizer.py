from __future__ import annotations

import json
import re
from typing import Any

try:
    from .redaction import redact_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.redaction import redact_text


MAX_STORED_TEXT = 1200
MAX_STORED_JSON_ITEMS = 60
MAX_STORED_JSON_DEPTH = 6


def safe_text(value: Any, limit: int = MAX_STORED_TEXT) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")
    text = redact_text(text, limit)
    if len(text) > limit:
        return text[: max(0, limit - 20)] + "...[truncated]"
    return text


def safe_json_value(value: Any, depth: int = 0) -> Any:
    if depth >= MAX_STORED_JSON_DEPTH:
        return safe_text(value, MAX_STORED_TEXT)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return safe_text(value, MAX_STORED_TEXT)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_STORED_JSON_ITEMS:
                result["...[truncated]"] = len(value) - MAX_STORED_JSON_ITEMS
                break
            safe_key = safe_text(key, 120)
            if is_sensitive_key(safe_key):
                result[safe_key] = "[redacted]"
            else:
                result[safe_key] = safe_json_value(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        result = [
            safe_json_value(item, depth + 1)
            for item in list(value)[:MAX_STORED_JSON_ITEMS]
        ]
        if len(value) > MAX_STORED_JSON_ITEMS:
            result.append(f"...[truncated {len(value) - MAX_STORED_JSON_ITEMS} items]")
        return result
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return safe_text(value)


def compact_json(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def is_sensitive_key(value: str) -> bool:
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", normalized).strip("_").lower()
    if not normalized:
        return False
    parts = {part for part in normalized.split("_") if part}
    compact = normalized.replace("_", "")
    if compact in {"authorization", "apikey", "xapikey", "bearertoken"}:
        return True
    if parts & {"token", "password", "passwd", "secret", "credential", "credentials"}:
        return True
    if "api" in parts and "key" in parts:
        return True
    if "private" in parts and "key" in parts:
        return True
    if "access" in parts and "key" in parts:
        return True
    if "refresh" in parts and "key" in parts:
        return True
    return False
