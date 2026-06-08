from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import aiohttp  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: aiohttp. Run `python -m pip install -r requirements.txt` "
        "in this plugin directory, or run this test inside the AstrBot environment."
    ) from exc


def install_fake_astrbot_modules() -> None:
    astrbot_mod = types.ModuleType("astrbot")
    api_mod = types.ModuleType("astrbot.api")
    event_mod = types.ModuleType("astrbot.api.event")
    star_mod = types.ModuleType("astrbot.api.star")
    core_mod = types.ModuleType("astrbot.core")
    message_mod = types.ModuleType("astrbot.core.message")
    result_mod = types.ModuleType("astrbot.core.message.message_event_result")
    platform_mod = types.ModuleType("astrbot.core.platform")
    session_mod = types.ModuleType("astrbot.core.platform.message_session")

    class FakeLogger:
        def warning(self, *args: Any, **_kwargs: Any) -> None:
            print("[warning]", *args)

        def exception(self, *args: Any, **_kwargs: Any) -> None:
            print("[exception]", *args)

    class FakeFilter:
        @staticmethod
        def command(_name: str):
            def decorator(func):
                return func

            return decorator

    class FakeStar:
        def __init__(self, context: Any) -> None:
            self.context = context

    class FakeContext:
        pass

    class FakeMessageChain:
        def __init__(self) -> None:
            self.text = ""

        def message(self, text: str):
            self.text += text
            return self

    class FakeMessageSession:
        def __init__(self, platform_id: str) -> None:
            self.platform_id = platform_id

        @classmethod
        def from_str(cls, value: str):
            platform_id = value.split(":", 1)[0] if ":" in value else value
            return cls(platform_id or "test")

    def register(*_args: Any, **_kwargs: Any):
        def decorator(cls):
            return cls

        return decorator

    api_mod.AstrBotConfig = dict
    api_mod.logger = FakeLogger()
    event_mod.AstrMessageEvent = object
    event_mod.filter = FakeFilter
    star_mod.Context = FakeContext
    star_mod.Star = FakeStar
    star_mod.register = register
    result_mod.MessageChain = FakeMessageChain
    session_mod.MessageSession = FakeMessageSession

    sys.modules.update(
        {
            "astrbot": astrbot_mod,
            "astrbot.api": api_mod,
            "astrbot.api.event": event_mod,
            "astrbot.api.star": star_mod,
            "astrbot.core": core_mod,
            "astrbot.core.message": message_mod,
            "astrbot.core.message.message_event_result": result_mod,
            "astrbot.core.platform": platform_mod,
            "astrbot.core.platform.message_session": session_mod,
        }
    )


install_fake_astrbot_modules()

from main import CloudCLIConnectorPlugin  # noqa: E402
from state import UserRef  # noqa: E402


class FakePlatformMeta:
    id = "test"


class FakePlatform:
    def __init__(self, outbox: list[str]) -> None:
        self.outbox = outbox

    def meta(self) -> FakePlatformMeta:
        return FakePlatformMeta()

    async def send_by_session(self, _session: Any, chain: Any) -> None:
        self.outbox.append(getattr(chain, "text", str(chain)))


class FakePlatformManager:
    def __init__(self, outbox: list[str]) -> None:
        self.platform_insts = [FakePlatform(outbox)]


class FakeContext:
    def __init__(self) -> None:
        self.outbox: list[str] = []
        self.platform_manager = FakePlatformManager(self.outbox)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def bool_env(name: str) -> bool:
    return env(name).lower() in {"1", "true", "yes", "on"}


class RealCloudCLICommandTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["ASTRBOT_DATA_PATH"] = self.temp_dir.name
        self.context = FakeContext()
        self.plugin = CloudCLIConnectorPlugin(
            self.context,
            {
                "cloudcli_base_url": env("CLOUDCLI_TEST_BASE_URL", env("CLOUDCLI_BASE_URL", "http://127.0.0.1:13002")),
                "cloudcli_jwt_token": env("CLOUDCLI_TEST_JWT_TOKEN", env("CLOUDCLI_JWT_TOKEN")),
                "cloudcli_username": env("CLOUDCLI_TEST_USERNAME", env("CLOUDCLI_USERNAME")),
                "cloudcli_password": env("CLOUDCLI_TEST_PASSWORD", env("CLOUDCLI_PASSWORD")),
                "cloudcli_api_key": env("CLOUDCLI_TEST_API_KEY", env("CLOUDCLI_API_KEY")),
                "auto_connect": False,
                "request_timeout_seconds": int(env("CLOUDCLI_TEST_TIMEOUT", "12")),
                "recent_sessions_limit": int(env("CLOUDCLI_TEST_RECENT_LIMIT", "20")),
                "chat_messages_limit": int(env("CLOUDCLI_TEST_CHAT_LIMIT", "8")),
                "run_status_interval_seconds": 1,
                "max_run_status_pushes": 5,
                "max_push_text_length": 3000,
            },
        )
        await self.plugin.initialize()
        self.user = UserRef(
            user_key="test:cloudcli-user",
            display_name="CloudCLI Test User",
            unified_msg_origin="test:cloudcli-user",
        )
        await self.plugin.state.remember_user(self.user)

    async def asyncTearDown(self) -> None:
        await self.plugin.terminate()
        self.temp_dir.cleanup()

    async def command(self, text: str) -> str:
        parsed = self.plugin._parse_command(text)
        result = await self.plugin._dispatch(parsed, self.user)
        print(f"\n>>> {text}\n{result}\n")
        return result

    async def pick_session_id(self) -> str:
        configured = env("CLOUDCLI_TEST_SESSION_ID")
        if configured:
            return configured

        sessions = await self.plugin.client.get_recent_sessions(20)
        if not sessions:
            self.fail(
                "CloudCLI 没有返回最近 session。请先在 CloudCLI Web UI 创建一个会话，"
                "或设置 CLOUDCLI_TEST_SESSION_ID。"
            )
        return str(sessions[0]["id"])

    async def test_real_cloudcli_command_flow(self) -> None:
        help_text = await self.command("/cloudcli help")
        self.assertIn("/cloudcli session", help_text)
        self.assertIn("/cloudcli chat", help_text)
        self.assertIn("/cloudcli run", help_text)

        session_text = await self.command("/cloudcli session")
        self.assertIn("CloudCLI 活跃 session", session_text)
        self.assertIn("最近可绑定 session", session_text)

        session_id = await self.pick_session_id()

        bind_text = await self.command(f"/cloudcli bind {session_id}")
        self.assertTrue("已绑定 session" in bind_text or "已绑定" in bind_text)

        bind_list_text = await self.command("/cloudcli bind list")
        self.assertIn(session_id, bind_list_text)

        chat_text = await self.command("/cloudcli chat 5")
        self.assertTrue(
            "CloudCLI session 最近消息" in chat_text or "暂无可展示消息" in chat_text,
            chat_text,
        )

        pending_text = await self.command("/cloudcli pending")
        self.assertTrue(
            "待审批权限" in pending_text
            or "没有待审批权限" in pending_text
            or "同步 CloudCLI 待审批权限失败" in pending_text,
            pending_text,
        )

        unbind_text = await self.command(f"/cloudcli unbind {session_id}")
        self.assertIn("已解绑 session", unbind_text)

    async def test_real_cloudcli_run_command_when_enabled(self) -> None:
        if not bool_env("CLOUDCLI_TEST_RUN_ENABLED"):
            self.skipTest("Set CLOUDCLI_TEST_RUN_ENABLED=1 to run /cloudcli run against real CloudCLI.")

        project = env("CLOUDCLI_TEST_RUN_PROJECT")
        github_url = env("CLOUDCLI_TEST_RUN_GITHUB")
        session_id = env("CLOUDCLI_TEST_SESSION_ID")
        provider = env("CLOUDCLI_TEST_RUN_PROVIDER", "claude")
        message = env(
            "CLOUDCLI_TEST_RUN_MESSAGE",
            "请只回复一句话：CloudCLI AstrBot 插件真实集成测试完成。不要修改任何文件。",
        )

        if project:
            command = f'/cloudcli run --project "{project}" --provider {provider} {message}'
        elif github_url:
            command = f"/cloudcli run --github {github_url} --provider {provider} {message}"
        elif session_id:
            command = f"/cloudcli run --session {session_id} --provider {provider} {message}"
        else:
            self.fail(
                "CLOUDCLI_TEST_RUN_ENABLED=1 时需要设置 CLOUDCLI_TEST_RUN_PROJECT、"
                "CLOUDCLI_TEST_RUN_GITHUB 或 CLOUDCLI_TEST_SESSION_ID。"
            )

        start_text = await self.command(command)
        self.assertIn("已启动 CloudCLI agent 任务", start_text)

        timeout_seconds = int(env("CLOUDCLI_TEST_RUN_WAIT", "120"))
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while self.plugin._background_tasks and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.5)

        self.assertFalse(self.plugin._background_tasks, "CloudCLI run background task did not finish in time.")
        pushed = "\n\n".join(self.context.outbox)
        print("\n--- proactive outbox ---\n" + pushed)
        self.assertIn("CloudCLI 任务", pushed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
