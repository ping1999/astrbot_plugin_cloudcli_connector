"""CloudCLI 客户端使用的异常类型。"""

from __future__ import annotations

from typing import Any

try:
    from ..core.redaction import redact_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.redaction import redact_text


class CloudCLIError(RuntimeError):
    """CloudCLI 通信、认证或协议错误的统一基类。"""

    def __init__(self, *args: Any) -> None:
        """异常消息在创建时就脱敏，避免调用方直接 `str(exc)` 时漏掉安全处理。"""
        super().__init__(*(_safe_error_arg(arg) for arg in args))


class CloudCLITimeout(CloudCLIError):
    """等待 CloudCLI 响应超时时抛出。"""

    pass


def _safe_error_arg(value: Any) -> Any:
    """只处理字符串参数，保留非字符串参数的原始语义。"""
    if isinstance(value, str):
        return redact_text(value)
    return value
