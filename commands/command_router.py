"""轻量命令路由：根据解析出的子命令选择对应 handler。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

try:
    from .command_parser import ParsedCommand
    from ..persistence.state_models import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from commands.command_parser import ParsedCommand
    from persistence.state_models import UserRef


CommandHandler = Callable[[UserRef, list[str]], Awaitable[str]]
ParsedCommandHandler = Callable[[UserRef, ParsedCommand], Awaitable[str]]


@dataclass(frozen=True)
class CommandRoute:
    """描述一条子命令路由及其参数约束。"""

    handler: CommandHandler | ParsedCommandHandler
    usage: str = ""
    no_args: bool = False
    pass_command: bool = False


class CommandRouter:
    """统一处理帮助、未知命令、参数数量错误和 handler 调用。"""

    def __init__(
        self,
        *,
        routes: dict[str, CommandRoute],
        help_text: str,
        help_names: set[str] | None = None,
    ) -> None:
        self.routes = routes
        self.help_text = help_text
        self.help_names = help_names or {"", "help", "-h", "--help"}

    async def dispatch(self, command: ParsedCommand, user: UserRef) -> str:
        """执行一条解析后的命令，返回最终要发送到聊天里的文本。"""
        if command.name in self.help_names:
            return self.help_text

        route = self.routes.get(command.name)
        if route is None:
            return f"未知指令：{command.name}\n\n{self.help_text}"

        if route.no_args and command.args:
            return route.usage
        if route.pass_command:
            return await route.handler(user, command)  # type: ignore[misc]
        return await route.handler(user, command.args)
