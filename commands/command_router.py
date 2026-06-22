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


@dataclass(frozen=True)
class CommandRoute:
    handler: CommandHandler
    usage: str = ""
    no_args: bool = False


class CommandRouter:
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
        if command.name in self.help_names:
            return self.help_text

        route = self.routes.get(command.name)
        if route is None:
            return f"未知指令：{command.name}\n\n{self.help_text}"

        if route.no_args and command.args:
            return route.usage
        return await route.handler(user, command.args)
