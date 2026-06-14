from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass
class ParsedCommand:
    name: str
    args: list[str]
    raw_args: str


def parse_command(message: str) -> ParsedCommand:
    stripped = message.strip()
    if not stripped:
        return ParsedCommand("", [], "")
    try:
        lexer = shlex.shlex(stripped, posix=False)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = [_strip_wrapping_quotes(token) for token in lexer]
    except ValueError:
        return ParsedCommand("help", [], "")
    if tokens and tokens[0].lstrip("/") == "cloudcli":
        tokens = tokens[1:]
    if not tokens:
        return ParsedCommand("help", [], "")
    raw_args = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ""
    return ParsedCommand(tokens[0].lower(), tokens[1:], raw_args)


def parse_optional_request_no(args: list[str]) -> tuple[int | None, str | None]:
    if not args:
        return None, None
    if not args[0].isdigit():
        return None, "序号必须是正整数。"
    value = int(args[0])
    if value < 1:
        return None, "序号必须从 1 开始。"
    return value, None


def parse_positive_int(
    value: str,
    name: str,
    minimum: int,
    maximum: int,
) -> tuple[int, str | None]:
    try:
        parsed = int(value)
    except ValueError:
        return minimum, f"{name} 必须是整数。"
    if parsed < minimum or parsed > maximum:
        return minimum, f"{name} 必须在 {minimum}-{maximum} 之间。"
    return parsed, None


def _strip_wrapping_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
