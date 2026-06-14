from __future__ import annotations

import asyncio
import ast
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any


TEST_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = TEST_DIR.parent
WORKSPACE_ROOT = PLUGIN_ROOT.parent
CONFIG_PATH = Path(os.environ.get("CLOUDCLI_TEST_CONFIG", TEST_DIR / "config.yaml"))
LEGACY_CONFIG_PATH = WORKSPACE_ROOT / "integration_tests" / "config.yaml"
if not CONFIG_PATH.exists() and LEGACY_CONFIG_PATH.exists():
    CONFIG_PATH = LEGACY_CONFIG_PATH
if not (PLUGIN_ROOT / "main.py").exists():
    raise SystemExit(f"Plugin source not found: {PLUGIN_ROOT}")
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

try:
    import aiohttp  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: aiohttp. Run "
        "`python -m pip install -r requirements.txt` from the plugin root, "
        "or run this test inside the AstrBot environment."
    ) from exc


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return load_simple_yaml(path)

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Failed to read config file {path}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise SystemExit(f"Config file must contain a mapping: {path}")
    return {str(key): value for key, value in loaded.items()}


def load_simple_yaml(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise SystemExit(f"Invalid config line {line_no}: expected `key: value`.")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"Invalid config line {line_no}: empty key.")
        data[key] = parse_simple_yaml_value(raw_value.strip())
    return data


def parse_simple_yaml_value(value: str) -> str:
    if " #" in value and not value.startswith(("'", '"')):
        value = value.split(" #", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
        return str(parsed)
    return value


CONFIG = load_config(CONFIG_PATH)
PRINT_OUTPUT_LIMIT = int(
    os.environ.get("CLOUDCLI_TEST_PRINT_OUTPUT_LIMIT")
    or CONFIG.get("print_output_limit")
    or 1200
)


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
        def __init__(self, platform_id: str, raw: str = "") -> None:
            self.platform_id = platform_id
            self.raw = raw

        @classmethod
        def from_str(cls, value: str):
            platform_id = value.split(":", 1)[0] if ":" in value else value
            return cls(platform_id or "test", value)

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
from command_parser import parse_command  # noqa: E402
from redaction import redact_text  # noqa: E402
from run_validation import looks_like_github_url  # noqa: E402
from state import PendingApproval, UserRef  # noqa: E402


class FakePlatformMeta:
    id = "test"


class FakePlatform:
    def __init__(self, outbox: list[str], sent_origins: list[str]) -> None:
        self.outbox = outbox
        self.sent_origins = sent_origins

    def meta(self) -> FakePlatformMeta:
        return FakePlatformMeta()

    async def send_by_session(self, session: Any, chain: Any) -> None:
        self.outbox.append(getattr(chain, "text", str(chain)))
        self.sent_origins.append(getattr(session, "raw", ""))


class FakePlatformManager:
    def __init__(self, outbox: list[str], sent_origins: list[str]) -> None:
        self.platform_insts = [FakePlatform(outbox, sent_origins)]


class FakeContext:
    def __init__(self) -> None:
        self.outbox: list[str] = []
        self.sent_origins: list[str] = []
        self.platform_manager = FakePlatformManager(self.outbox, self.sent_origins)


def setting(config_key: str | tuple[str, ...], env_names: tuple[str, ...], default: str = "") -> str:
    for env_name in env_names:
        env_value = os.environ.get(env_name)
        if env_value is not None and env_value.strip():
            return env_value.strip()

    keys = (config_key,) if isinstance(config_key, str) else config_key
    for key in keys:
        value = CONFIG.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def bool_setting(config_key: str | tuple[str, ...], env_names: tuple[str, ...], default: bool = False) -> bool:
    value = setting(config_key, env_names, "true" if default else "false")
    return value.lower() in {"1", "true", "yes", "on"}


def has_real_cloudcli_config() -> bool:
    has_token = bool(setting(("jwt_token", "cloudcli_jwt_token"), ("CLOUDCLI_TEST_JWT_TOKEN", "CLOUDCLI_JWT_TOKEN")))
    has_login = bool(
        setting(("username", "cloudcli_username"), ("CLOUDCLI_TEST_USERNAME", "CLOUDCLI_USERNAME"))
        and setting(("password", "cloudcli_password"), ("CLOUDCLI_TEST_PASSWORD", "CLOUDCLI_PASSWORD"))
    )
    return has_token or has_login


def safe_print(text: str) -> None:
    encoding = sys.stdout.encoding or "utf-8"
    safe_text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(safe_text)


def format_command_output(command: str, result: str) -> str:
    rendered = result
    if PRINT_OUTPUT_LIMIT > 0 and len(rendered) > PRINT_OUTPUT_LIMIT:
        rendered = rendered[:PRINT_OUTPUT_LIMIT] + f"\n... truncated {len(result) - PRINT_OUTPUT_LIMIT} chars"
    return f"\n>>> {command}\n{rendered}\n"


def plugin_config(**overrides: Any) -> dict[str, Any]:
    config = {
        "cloudcli_base_url": setting("base_url", ("CLOUDCLI_TEST_BASE_URL", "CLOUDCLI_BASE_URL"), "http://127.0.0.1:13002"),
        "cloudcli_jwt_token": setting(("jwt_token", "cloudcli_jwt_token"), ("CLOUDCLI_TEST_JWT_TOKEN", "CLOUDCLI_JWT_TOKEN")),
        "cloudcli_username": setting(("username", "cloudcli_username"), ("CLOUDCLI_TEST_USERNAME", "CLOUDCLI_USERNAME")),
        "cloudcli_password": setting(("password", "cloudcli_password"), ("CLOUDCLI_TEST_PASSWORD", "CLOUDCLI_PASSWORD")),
        "cloudcli_api_key": setting(("api_key", "cloudcli_api_key"), ("CLOUDCLI_TEST_API_KEY", "CLOUDCLI_API_KEY")),
        "auto_connect": False,
        "request_timeout_seconds": int(setting(("timeout", "request_timeout_seconds"), ("CLOUDCLI_TEST_TIMEOUT",), "12")),
        "recent_sessions_limit": int(setting("recent_sessions_limit", ("CLOUDCLI_TEST_RECENT_LIMIT",), "20")),
        "chat_messages_limit": int(setting("chat_messages_limit", ("CLOUDCLI_TEST_CHAT_LIMIT",), "8")),
        "run_status_interval_seconds": 1,
        "max_run_status_pushes": 5,
        "run_list_limit": 10,
        "approval_timeout_seconds": int(setting("approval_timeout_seconds", ("CLOUDCLI_TEST_APPROVAL_TIMEOUT",), "0")),
        "approval_timeout_action": setting("approval_timeout_action", ("CLOUDCLI_TEST_APPROVAL_TIMEOUT_ACTION",), "remind"),
        "approval_allowed_user_keys": setting("approval_allowed_user_keys", ("CLOUDCLI_TEST_APPROVAL_ALLOWED_USER_KEYS",)),
        "allowed_project_roots": setting("allowed_project_roots", ("CLOUDCLI_TEST_ALLOWED_PROJECT_ROOTS",)),
        "max_push_text_length": 3000,
    }
    config.update(overrides)
    return config


class RealCloudCLICommandTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self._old_data_path = os.environ.get("ASTRBOT_DATA_PATH")
        os.environ["ASTRBOT_DATA_PATH"] = self.temp_dir.name
        self.context = FakeContext()
        self.plugin = CloudCLIConnectorPlugin(
            self.context,
            plugin_config(),
        )
        await self.plugin.initialize()
        self.user = UserRef(
            user_key="test:cloudcli-user",
            display_name="CloudCLI Test User",
            unified_msg_origin="test:cloudcli-user",
            is_admin=True,
        )
        await self.plugin.state.remember_user(self.user)

    async def asyncTearDown(self) -> None:
        await self.plugin.terminate()
        if self._old_data_path is None:
            os.environ.pop("ASTRBOT_DATA_PATH", None)
        else:
            os.environ["ASTRBOT_DATA_PATH"] = self._old_data_path
        self.temp_dir.cleanup()

    async def command(self, text: str) -> str:
        parsed = parse_command(text)
        result = await self.plugin._dispatch(parsed, self.user)
        safe_print(format_command_output(text, result))
        return result

    async def pick_session_id(self) -> str:
        configured = setting("session_id", ("CLOUDCLI_TEST_SESSION_ID",))
        if configured:
            return configured

        sessions = await self.plugin.client.get_recent_sessions(20)
        if not sessions:
            self.fail(
                "CloudCLI 没有返回最近 session。请先在 CloudCLI Web UI 创建一个会话，"
                "或设置 CLOUDCLI_TEST_SESSION_ID。"
        )
        return str(sessions[0]["id"])

    def test_security_regression_redaction_and_url_validation(self) -> None:
        rendered = redact_text('{"api_key": "secret-value", "password": "pw-value"}')
        self.assertIn("[redacted]", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("pw-value", rendered)

        self.assertTrue(looks_like_github_url("https://github.com/example/repo"))
        self.assertTrue(looks_like_github_url("git@github.com:example/repo.git"))
        self.assertFalse(looks_like_github_url("https://github.com.evil/repo"))
        self.assertFalse(looks_like_github_url("https://example.com/repo"))

    async def test_security_regression_approval_push_targeting_and_redaction(self) -> None:
        strict_context = FakeContext()
        strict_plugin = CloudCLIConnectorPlugin(
            strict_context,
            plugin_config(
                approval_allowed_user_keys="",
                approval_require_admin=True,
                approval_timeout_seconds=0,
            ),
        )
        await strict_plugin.initialize()
        try:
            strict_user = UserRef(
                user_key="test:strict-admin",
                display_name="Strict Admin",
                unified_msg_origin="test:private-origin",
                is_admin=True,
            )
            await strict_plugin.state.remember_user(strict_user)
            await strict_plugin.state.bind_session(strict_user, "security-session-1", 5)
            await strict_plugin.state.remember_user(
                UserRef(
                    user_key=strict_user.user_key,
                    display_name=strict_user.display_name,
                    unified_msg_origin="test:group-origin",
                    is_admin=True,
                )
            )
            await strict_plugin._on_permission_request(
                PendingApproval(
                    request_id="security-request-1",
                    session_id="security-session-1",
                    tool_name="SecurityTool",
                    input_data={"api_key": "secret-value"},
                )
            )
            self.assertEqual([], strict_context.outbox)
            self.assertEqual([], strict_context.sent_origins)
        finally:
            await strict_plugin.terminate()

        allow_context = FakeContext()
        allow_plugin = CloudCLIConnectorPlugin(
            allow_context,
            plugin_config(
                approval_allowed_user_keys="test:allowlisted",
                approval_require_admin=True,
                approval_timeout_seconds=0,
            ),
        )
        await allow_plugin.initialize()
        try:
            allow_user = UserRef(
                user_key="test:allowlisted",
                display_name="Allowlisted User",
                unified_msg_origin="test:private-allowlisted",
                is_admin=False,
            )
            await allow_plugin.state.remember_user(allow_user)
            await allow_plugin.state.bind_session(allow_user, "security-session-2", 5)
            await allow_plugin.state.remember_user(
                UserRef(
                    user_key=allow_user.user_key,
                    display_name=allow_user.display_name,
                    unified_msg_origin="test:group-allowlisted",
                    is_admin=False,
                )
            )
            await allow_plugin._on_permission_request(
                PendingApproval(
                    request_id="security-request-2",
                    session_id="security-session-2",
                    tool_name="SecurityTool",
                    input_data={"api_key": "secret-value"},
                )
            )
            self.assertEqual(["test:private-allowlisted"], allow_context.sent_origins)
            self.assertEqual(1, len(allow_context.outbox))
            self.assertIn("[redacted]", allow_context.outbox[0])
            self.assertNotIn("secret-value", allow_context.outbox[0])
        finally:
            await allow_plugin.terminate()

    async def test_security_regression_project_path_realpath_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            allowed = base / "allowed"
            outside = base / "outside"
            allowed.mkdir()
            outside.mkdir()
            escape = allowed / "escape"
            try:
                escape.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Directory symlink unavailable in this environment: {exc}")

            plugin = CloudCLIConnectorPlugin(
                FakeContext(),
                plugin_config(
                    allowed_project_roots=str(allowed),
                    approval_timeout_seconds=0,
                ),
            )
            path_error = plugin.authz.validate_project_path(
                UserRef(
                    user_key="test:path-user",
                    display_name="Path User",
                    unified_msg_origin="test:path-user",
                    is_admin=False,
                ),
                str(escape),
            )
            self.assertIn("projectPath 不在 allowed_project_roots", path_error)

    async def test_real_cloudcli_command_flow(self) -> None:
        if not has_real_cloudcli_config():
            self.skipTest(
                "Set CLOUDCLI_TEST_JWT_TOKEN or CLOUDCLI_TEST_USERNAME/CLOUDCLI_TEST_PASSWORD "
                "to run the real CloudCLI command flow."
            )

        help_text = await self.command("/cloudcli help")
        self.assertIn("/cloudcli status", help_text)
        self.assertIn("/cloudcli session", help_text)
        self.assertIn("/cloudcli chat", help_text)
        self.assertIn("/cloudcli run", help_text)
        self.assertIn("/cloudcli stop", help_text)
        self.assertIn("/cloudcli audit", help_text)

        whoami_text = await self.command("/cloudcli whoami")
        self.assertIn(self.user.user_key, whoami_text)
        self.assertIn("AstrBot 管理员：是", whoami_text)

        status_text = await self.command("/cloudcli status")
        self.assertIn("CloudCLI 状态", status_text)
        self.assertIn("WebSocket", status_text)
        self.assertIn("REST", status_text)

        run_list_empty = await self.command("/cloudcli run list")
        self.assertTrue(
            "CloudCLI 任务" in run_list_empty or "还没有 CloudCLI 任务" in run_list_empty,
            run_list_empty,
        )

        session_text = await self.command("/cloudcli session")
        self.assertIn("CloudCLI 活跃 session", session_text)
        self.assertIn("最近可绑定 session", session_text)

        configured_session_id = setting("session_id", ("CLOUDCLI_TEST_SESSION_ID",))
        if configured_session_id:
            session_id = configured_session_id
            bind_ref = configured_session_id
        else:
            resolved, error = await self.plugin.state.resolve_session_ref(self.user, "1")
            if error or not resolved:
                self.fail(error or "无法从 /cloudcli session 结果中解析第 1 个 session。")
            session_id = resolved["id"]
            bind_ref = "1"

        bind_text = await self.command(f"/cloudcli bind {bind_ref}")
        self.assertTrue("已绑定 session" in bind_text or "已绑定" in bind_text)

        bind_list_text = await self.command("/cloudcli bind list")
        self.assertIn(session_id, bind_list_text)

        bad_stop_text = await self.command(f"/cloudcli stop {session_id} invalid-provider")
        self.assertIn("provider 不支持", bad_stop_text)

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

        approval = PendingApproval(
            request_id="integration-test-request",
            session_id=session_id,
            tool_name="IntegrationTestTool",
            input_data={"note": "synthetic audit record; no CloudCLI decision is sent"},
        )
        await self.plugin.state.append_audit(
            user=self.user,
            action="allow",
            approval=approval,
            result="synthetic-test",
        )
        audit_text = await self.command("/cloudcli audit 5")
        self.assertIn("审批审计记录", audit_text)
        self.assertIn("IntegrationTestTool", audit_text)

        non_admin_user = UserRef(
            user_key="test:non-admin",
            display_name="Non Admin Test User",
            unified_msg_origin="test:non-admin",
            is_admin=False,
        )
        await self.plugin.state.remember_user(non_admin_user)
        parsed = parse_command("/cloudcli allow")
        blocked_allow = await self.plugin._dispatch(parsed, non_admin_user)
        safe_print(format_command_output("/cloudcli allow (non-admin)", blocked_allow))
        self.assertIn("没有权限审批", blocked_allow)

        unbind_text = await self.command(f"/cloudcli unbind {session_id}")
        self.assertIn("已解绑 session", unbind_text)

    async def test_real_cloudcli_run_command_when_enabled(self) -> None:
        if not bool_setting("run_enabled", ("CLOUDCLI_TEST_RUN_ENABLED",)):
            self.skipTest("Set CLOUDCLI_TEST_RUN_ENABLED=1 to run /cloudcli run against real CloudCLI.")
        if not has_real_cloudcli_config():
            self.skipTest("Real /cloudcli run needs CloudCLI credentials.")

        project = setting("run_project", ("CLOUDCLI_TEST_RUN_PROJECT",))
        github_url = setting("run_github", ("CLOUDCLI_TEST_RUN_GITHUB",))
        session_id = setting("session_id", ("CLOUDCLI_TEST_SESSION_ID",))
        provider = setting("run_provider", ("CLOUDCLI_TEST_RUN_PROVIDER",), "claude")
        message = setting(
            "run_message",
            ("CLOUDCLI_TEST_RUN_MESSAGE",),
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
        task_id = extract_task_id(start_text)
        self.assertTrue(task_id, start_text)

        run_list_text = await self.command("/cloudcli run list")
        self.assertIn(f"#{task_id}", run_list_text)

        run_log_text = await self.command(f"/cloudcli run log {task_id}")
        self.assertIn(f"任务 #{task_id} 日志", run_log_text)

        if bool_setting("run_cancel_enabled", ("CLOUDCLI_TEST_RUN_CANCEL_ENABLED",)):
            cancel_text = await self.command(f"/cloudcli run cancel {task_id}")
            self.assertTrue(
                "已取消 CloudCLI 任务" in cancel_text or "已经是" in cancel_text,
                cancel_text,
            )
            return

        timeout_seconds = int(setting("run_wait", ("CLOUDCLI_TEST_RUN_WAIT",), "120"))
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while self.plugin._background_tasks and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.5)

        self.assertFalse(self.plugin._background_tasks, "CloudCLI run background task did not finish in time.")
        pushed = "\n\n".join(self.context.outbox)
        safe_print(format_command_output("proactive outbox", pushed))
        self.assertIn("CloudCLI 任务", pushed)

        final_log_text = await self.command(f"/cloudcli run log {task_id}")
        self.assertIn(f"任务 #{task_id} 日志", final_log_text)

    async def test_real_cloudcli_stop_command_when_enabled(self) -> None:
        if not bool_setting("stop_enabled", ("CLOUDCLI_TEST_STOP_ENABLED",)):
            self.skipTest("Set CLOUDCLI_TEST_STOP_ENABLED=1 to send abort-session to real CloudCLI.")
        if not has_real_cloudcli_config():
            self.skipTest("Real /cloudcli stop needs CloudCLI credentials.")

        await self.command("/cloudcli session")
        session_ref = setting(("stop_session_ref", "stop_session_id", "session_id"), ("CLOUDCLI_TEST_STOP_SESSION_REF", "CLOUDCLI_TEST_STOP_SESSION_ID", "CLOUDCLI_TEST_SESSION_ID"), "1")
        provider = setting("stop_provider", ("CLOUDCLI_TEST_STOP_PROVIDER",), "")
        command = f"/cloudcli stop {session_ref}"
        if provider:
            command += f" {provider}"

        stop_text = await self.command(command)
        self.assertIn("已向 CloudCLI 发送中止 session 请求", stop_text)


def extract_task_id(text: str) -> str:
    match = re.search(r"task=#(\d+)", text)
    return match.group(1) if match else ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
