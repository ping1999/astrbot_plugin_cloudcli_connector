from __future__ import annotations

import re
import traceback


DEFAULT_MAX_REDACTED_TEXT_CHARS = 2000

_SECRET_SUBSTITUTIONS = (
    (r"(?i)\b(https?://)[^/\s@]+@", r"\1[redacted]@"),
    (
        r"(?i)((?:\"|')?(?:authorization|x-api-key|api[_-]?key|apikey|jwt[_-]?token|"
        r"access[_-]?token|refresh[_-]?token|token|password|passwd|secret|"
        r"credential|credentials|private[_-]?key)(?:\"|')?\s*:\s*(?:\"|'))"
        r"[^\"']+((?:\"|'))",
        r"\1[redacted]\2",
    ),
    (r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(x-api-key\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(apikey\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(jwt[_-]?token\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(access[_-]?token\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(refresh[_-]?token\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(token\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(password\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(passwd\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(secret\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(credential[s]?\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)(private[_-]?key\s*[:=]\s*)[^\s,'\"}]+", r"\1[redacted]"),
    (r"(?i)([?&](?:token|api_key|apikey|password|passwd|secret|credential|credentials|private_key)=)[^&\s]+", r"\1[redacted]"),
)


def redact_text(value: str, max_chars: int = DEFAULT_MAX_REDACTED_TEXT_CHARS) -> str:
    if not value:
        return ""
    text = value
    for pattern, replacement in _SECRET_SUBSTITUTIONS:
        text = re.sub(pattern, replacement, text)
    if max_chars > 0 and len(text) > max_chars:
        text = text[:max_chars] + "...[truncated]"
    return text


def redact_exception_text(exc: BaseException, max_chars: int = 8000) -> str:
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return redact_text(rendered, max_chars)
