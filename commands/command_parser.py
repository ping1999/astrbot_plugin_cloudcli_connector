"""命令行风格解析器：把聊天消息拆成命令名、参数列表和原始尾部文本。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandToken:
    """一个解析后的命令片段，同时保留它在原始字符串中的起止位置。"""

    value: str
    start: int
    end: int


@dataclass
class ParsedCommand:
    """供命令路由消费的标准结构。"""

    name: str
    args: list[str]
    raw_args: str


def parse_command(message: str) -> ParsedCommand:
    """解析整条消息，兼容带 `/cloudcli` 前缀和直接传入子命令两种形式。"""
    stripped = message.strip()
    if not stripped:
        return ParsedCommand("", [], "")
    try:
        parts = tokenize_command_parts_with_raw_tail(stripped)
    except ValueError:
        return ParsedCommand("help", [], "")
    if parts and parts[0].value.lstrip("/") == "cloudcli":
        parts = parts[1:]
    if not parts:
        return ParsedCommand("help", [], "")
    command = parts[0]
    raw_args = stripped[command.end :].strip()
    return ParsedCommand(command.value.lower(), [part.value for part in parts[1:]], raw_args)


def tokenize_command(value: str) -> list[str]:
    """只返回 token 值的简化入口，适合不关心原始位置的调用方。"""
    return [part.value for part in tokenize_command_parts(value)]


def tokenize_command_parts_with_raw_tail(value: str) -> list[CommandToken]:
    """解析参数，并把独立的 `--` 后面的内容作为原样任务文本保留下来。"""
    raw_tail_at = _find_standalone_double_dash(value)
    if raw_tail_at < 0:
        return tokenize_command_parts(value)

    before = value[:raw_tail_at].rstrip()
    parts = tokenize_command_parts(before) if before else []
    parts.append(CommandToken("--", raw_tail_at, raw_tail_at + 2))

    raw_tail = value[raw_tail_at + 2 :]
    if raw_tail.strip():
        leading = len(raw_tail) - len(raw_tail.lstrip())
        trailing = len(raw_tail) - len(raw_tail.rstrip())
        start = raw_tail_at + 2 + leading
        end = len(value) - trailing
        parts.append(CommandToken(value[start:end], start, end))
    return parts


def tokenize_command_parts(value: str) -> list[CommandToken]:
    """按空白切分参数，支持单引号和双引号包裹的空白内容。"""
    tokens: list[CommandToken] = []
    current: list[str] = []
    token_start: int | None = None
    quote = ""

    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
            continue

        if char in {"'", '"'}:
            if token_start is None:
                token_start = index
            quote = char
            continue

        if char.isspace():
            if token_start is not None:
                tokens.append(CommandToken("".join(current), token_start, index))
                current = []
                token_start = None
            continue

        if token_start is None:
            token_start = index
        current.append(char)

    if quote:
        raise ValueError("unclosed quote")
    if token_start is not None:
        tokens.append(CommandToken("".join(current), token_start, len(value)))
    return tokens


def _find_standalone_double_dash(value: str) -> int:
    """寻找不在引号内、且前后由空白分隔的 `--` 分隔符。"""
    quote = ""
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if (
            char == "-"
            and index + 1 < len(value)
            and value[index + 1] == "-"
            and (index == 0 or value[index - 1].isspace())
            and (index + 2 == len(value) or value[index + 2].isspace())
        ):
            return index
        index += 1
    return -1


def parse_optional_request_no(args: list[str]) -> tuple[int | None, str | None]:
    """解析审批序号；未传序号时返回 None，让上层在只有一条审批时自动选择。"""
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
    """解析带上下限的整数，并返回适合直接展示给用户的错误信息。"""
    try:
        parsed = int(value)
    except ValueError:
        return minimum, f"{name} 必须是整数。"
    if parsed < minimum or parsed > maximum:
        return minimum, f"{name} 必须在 {minimum}-{maximum} 之间。"
    return parsed, None
