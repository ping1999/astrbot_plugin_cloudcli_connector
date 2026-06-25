"""可选的 CloudCLI 实机命令测试：默认只跑安全离线回归，真实请求需在 config.yaml 显式开启。"""

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
CONFIG_PATH = TEST_DIR / "config.yaml"
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
    """读取 tests/config.yaml；缺文件时返回空配置，让真实 CloudCLI 测试自动跳过。"""
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
    """在未安装 PyYAML 时解析最简单的 `key: value` 配置文件。"""
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
    """解析简单 YAML 值，支持引号和行尾注释。"""
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
    CONFIG.get("print_output_limit")
    or 1200
)


def install_fake_astrbot_modules() -> None:
    """安装一组最小 AstrBot 假模块，让插件能在普通 Python 环境中导入。"""
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
        """测试用 logger，直接把警告输出到控制台便于调试。"""

        def warning(self, *args: Any, **_kwargs: Any) -> None:
            """记录 warning 日志。"""
            print("[warning]", *args)

        def exception(self, *args: Any, **_kwargs: Any) -> None:
            """记录 exception 日志。"""
            print("[exception]", *args)

    class FakeFilter:
        """模拟 AstrBot 的命令装饰器。"""

        @staticmethod
        def command(_name: str):
            """返回不改变函数本身的装饰器。"""
            def decorator(func):
                """保持被装饰函数原样返回。"""
                return func

            return decorator

    class FakeStar:
        """模拟 AstrBot Star 基类，只保存 context。"""

        def __init__(self, context: Any) -> None:
            self.context = context

    class FakeContext:
        """占位 Context 类型，供类型导入使用。"""

        pass

    class FakeMessageChain:
        """模拟 AstrBot MessageChain，测试只关心最终文本。"""

        def __init__(self) -> None:
            """初始化空消息文本。"""
            self.text = ""

        def message(self, text: str):
            """追加文本并返回自身，模拟链式 API。"""
            self.text += text
            return self

    class FakeMessageSession:
        """模拟主动推送所需的 MessageSession。"""

        def __init__(self, platform_id: str, raw: str = "") -> None:
            """保存平台 ID 和原始 origin 字符串。"""
            self.platform_id = platform_id
            self.raw = raw

        @classmethod
        def from_str(cls, value: str):
            """从 unified_msg_origin 中解析平台 ID。"""
            platform_id = value.split(":", 1)[0] if ":" in value else value
            return cls(platform_id or "test", value)

    def register(*_args: Any, **_kwargs: Any):
        """模拟插件注册装饰器，直接返回原类。"""
        def decorator(cls):
            """保持插件类原样返回。"""
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
from commands.command_parser import parse_command  # noqa: E402
from core.redaction import redact_text  # noqa: E402
from persistence.state_models import PendingApproval, UserRef  # noqa: E402
from security.run_validation import looks_like_github_url  # noqa: E402


class FakePlatformMeta:
    """测试平台元数据，平台 ID 固定为 test。"""

    id = "test"


class FakePlatform:
    """模拟 AstrBot 平台实例，把主动推送写入 outbox。"""

    def __init__(self, outbox: list[str], sent_origins: list[str]) -> None:
        self.outbox = outbox
        self.sent_origins = sent_origins

    def meta(self) -> FakePlatformMeta:
        """返回平台元数据。"""
        return FakePlatformMeta()

    async def send_by_session(self, session: Any, chain: Any) -> None:
        """记录主动推送文本和目标 origin。"""
        self.outbox.append(getattr(chain, "text", str(chain)))
        self.sent_origins.append(getattr(session, "raw", ""))


class FakePlatformManager:
    """模拟 AstrBot platform_manager，包含一个 FakePlatform。"""

    def __init__(self, outbox: list[str], sent_origins: list[str]) -> None:
        """把共享 outbox 交给平台实例。"""
        self.platform_insts = [FakePlatform(outbox, sent_origins)]


class FakeContext:
    """插件测试上下文，收集主动推送的文本和目标会话。"""

    def __init__(self) -> None:
        """创建主动推送收件箱和 fake platform manager。"""
        self.outbox: list[str] = []
        self.sent_origins: list[str] = []
        self.platform_manager = FakePlatformManager(self.outbox, self.sent_origins)


def setting(config_key: str | tuple[str, ...], default: str = "") -> str:
    """读取测试配置；支持多个候选 key 以兼容旧配置名。"""
    keys = (config_key,) if isinstance(config_key, str) else config_key
    for key in keys:
        value = CONFIG.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def bool_setting(config_key: str | tuple[str, ...], default: bool = False) -> bool:
    """按常见布尔字符串读取测试开关。"""
    value = setting(config_key, "true" if default else "false")
    return value.lower() in {"1", "true", "yes", "on"}


def real_cloudcli_enabled() -> bool:
    """是否允许本文件中的真实 CloudCLI 请求测试运行。"""
    return bool_setting("real_enabled")


def has_real_cloudcli_config() -> bool:
    """真实测试需要 real_enabled=true 且配置 JWT 或用户名密码。"""
    if not real_cloudcli_enabled():
        return False
    has_token = bool(setting(("jwt_token", "cloudcli_jwt_token")))
    has_login = bool(
        setting(("username", "cloudcli_username"))
        and setting(("password", "cloudcli_password"))
    )
    return has_token or has_login


def safe_print(text: str) -> None:
    """按当前终端编码安全输出测试日志，避免 Windows 控制台编码异常。"""
    encoding = sys.stdout.encoding or "utf-8"
    safe_text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(safe_text)


def format_command_output(command: str, result: str) -> str:
    """把一条测试命令和响应格式化为可读日志，并按配置裁剪输出。"""
    rendered = result
    if PRINT_OUTPUT_LIMIT > 0 and len(rendered) > PRINT_OUTPUT_LIMIT:
        rendered = rendered[:PRINT_OUTPUT_LIMIT] + f"\n... truncated {len(result) - PRINT_OUTPUT_LIMIT} chars"
    return f"\n>>> {command}\n{rendered}\n"


def plugin_config(**overrides: Any) -> dict[str, Any]:
    """构造插件配置，默认关闭自动连接和超时审批，测试按需覆盖。"""
    config = {
        "cloudcli_base_url": setting("base_url", "http://127.0.0.1:13002"),
        "cloudcli_jwt_token": setting(("jwt_token", "cloudcli_jwt_token")),
        "cloudcli_username": setting(("username", "cloudcli_username")),
        "cloudcli_password": setting(("password", "cloudcli_password")),
        "cloudcli_api_key": setting(("api_key", "cloudcli_api_key")),
        "auto_connect": False,
        "request_timeout_seconds": int(setting(("timeout", "request_timeout_seconds"), "12")),
        "recent_sessions_limit": int(setting("recent_sessions_limit", "20")),
        "chat_messages_limit": int(setting("chat_messages_limit", "8")),
        "run_status_interval_seconds": 1,
        "max_run_status_pushes": 5,
        "run_list_limit": 10,
        "approval_timeout_seconds": int(setting("approval_timeout_seconds", "0")),
        "approval_timeout_action": setting("approval_timeout_action", "remind"),
        "approval_allowed_user_keys": setting("approval_allowed_user_keys"),
        "approval_access_mode": setting("approval_access_mode", "admin_or_allowlist"),
        "approval_allow_direct_session_bind": setting("approval_allow_direct_session_bind", "false").lower() == "true",
        "session_access_mode": setting("session_access_mode", "admin_or_allowlist"),
        "run_access_mode": setting("run_access_mode", "admin_or_allowlist"),
        "allowed_project_roots": setting("allowed_project_roots"),
        "max_push_text_length": 3000,
    }
    config.update(overrides)
    return config


class RealCloudCLICommandTest(unittest.IsolatedAsyncioTestCase):
    """模拟 AstrBot 中的 `/cloudcli` 命令流，并可选连接真实 CloudCLI。"""

    async def asyncSetUp(self) -> None:
        """为每个测试创建隔离的数据目录、插件实例和管理员测试用户。"""
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
        """关闭插件并恢复 ASTRBOT_DATA_PATH。"""
        await self.plugin.terminate()
        if self._old_data_path is None:
            os.environ.pop("ASTRBOT_DATA_PATH", None)
        else:
            os.environ["ASTRBOT_DATA_PATH"] = self._old_data_path
        self.temp_dir.cleanup()

    async def command(self, text: str) -> str:
        """直接调用插件路由执行一条 `/cloudcli` 命令，并打印可读输出。"""
        parsed = parse_command(text)
        result = await self.plugin._dispatch(parsed, self.user)
        safe_print(format_command_output(text, result))
        return result

    async def pick_session_id(self) -> str:
        """优先使用配置的 session_id，否则从真实 CloudCLI 最近 session 中挑一个。"""
        configured = setting("session_id")
        if configured:
            return configured

        sessions = await self.plugin.client.get_recent_sessions(20)
        if not sessions:
            self.fail(
                "CloudCLI 没有返回最近 session。请先在 CloudCLI Web UI 创建一个会话，"
                "或在 tests/config.yaml 设置 session_id。"
        )
        return str(sessions[0]["id"])

    def test_security_regression_redaction_and_url_validation(self) -> None:
        """离线安全回归：脱敏函数和 GitHub URL 白名单不依赖真实 CloudCLI。"""
        rendered = redact_text('{"api_key": "secret-value", "password": "pw-value"}')
        self.assertIn("[redacted]", rendered)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("pw-value", rendered)

        self.assertTrue(looks_like_github_url("https://github.com/example/repo"))
        self.assertTrue(looks_like_github_url("git@github.com:example/repo.git"))
        self.assertFalse(looks_like_github_url("https://github.com.evil/repo"))
        self.assertFalse(looks_like_github_url("https://example.com/repo"))

    async def test_security_regression_approval_push_targeting_and_redaction(self) -> None:
        """离线安全回归：审批详情只推给允许用户，且工具输入中的 secret 会被脱敏。"""
        async def isolated_plugin(context: FakeContext, **overrides: Any):
            """为额外插件实例分配独立数据目录，避免触发运行期独占锁。"""
            data_dir = tempfile.TemporaryDirectory()
            old_data_path = os.environ.get("ASTRBOT_DATA_PATH")
            os.environ["ASTRBOT_DATA_PATH"] = data_dir.name
            try:
                plugin = CloudCLIConnectorPlugin(context, plugin_config(**overrides))
            finally:
                if old_data_path is None:
                    os.environ.pop("ASTRBOT_DATA_PATH", None)
                else:
                    os.environ["ASTRBOT_DATA_PATH"] = old_data_path
            await plugin.initialize()
            return plugin, data_dir

        strict_context = FakeContext()
        strict_plugin, strict_data_dir = await isolated_plugin(
            strict_context,
            approval_allowed_user_keys="",
            approval_require_admin=True,
            approval_timeout_seconds=0,
        )
        try:
            # 未进入审批白名单时，即使用户是管理员且绑定了 session，也不应收到详细工具输入。
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
            strict_data_dir.cleanup()

        allow_context = FakeContext()
        allow_plugin, allow_data_dir = await isolated_plugin(
            allow_context,
            approval_allowed_user_keys="test:allowlisted",
            approval_require_admin=True,
            approval_timeout_seconds=0,
        )
        try:
            # 明确白名单用户可以收到审批详情，但消息内容仍需要通过 redaction。
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
            allow_data_dir.cleanup()

    async def test_security_regression_project_path_realpath_rejects_symlink_escape(self) -> None:
        """离线安全回归：allowed_project_roots 要按真实路径拒绝符号链接逃逸。"""
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
        """真实 CloudCLI 烟测：覆盖 help/status/session/bind/chat/pending/audit/unbind。"""
        if not has_real_cloudcli_config():
            self.skipTest(
                "Set real_enabled=true plus jwt_token or username/password in tests/config.yaml "
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

        configured_session_id = setting("session_id")
        if configured_session_id:
            session_id = configured_session_id
            bind_ref = configured_session_id
        else:
            # 没显式配置 session_id 时，使用 `/cloudcli session` 缓存的第一个最近 session。
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
        # 真实环境测试也顺手确认非管理员无法直接审批。
        self.assertIn("没有权限审批", blocked_allow)

        unbind_text = await self.command(f"/cloudcli unbind {session_id}")
        self.assertIn("已解绑 session", unbind_text)

    async def test_real_cloudcli_run_command_when_enabled(self) -> None:
        """可选真实 run 测试：需要 run_enabled=true，并会实际启动 CloudCLI agent 任务。"""
        if not bool_setting("run_enabled"):
            self.skipTest("Set run_enabled=true in tests/config.yaml to run /cloudcli run against real CloudCLI.")
        if not has_real_cloudcli_config():
            self.skipTest("Real /cloudcli run needs CloudCLI credentials.")

        project = setting("run_project")
        github_url = setting("run_github")
        session_id = setting("session_id")
        provider = setting("run_provider", "claude")
        message = setting(
            "run_message",
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
                "run_enabled=true 时需要在 tests/config.yaml 设置 run_project、run_github 或 session_id。"
            )

        start_text = await self.command(command)
        self.assertIn("已启动 CloudCLI agent 任务", start_text)
        task_id = extract_task_id(start_text)
        self.assertTrue(task_id, start_text)

        run_list_text = await self.command("/cloudcli run list")
        self.assertIn(f"#{task_id}", run_list_text)

        run_log_text = await self.command(f"/cloudcli run log {task_id}")
        self.assertIn(f"任务 #{task_id} 日志", run_log_text)

        if bool_setting("run_cancel_enabled"):
            # run_cancel_enabled 用于验证取消路径；默认不取消，等待任务自然结束并检查主动推送。
            cancel_text = await self.command(f"/cloudcli run cancel {task_id}")
            self.assertTrue(
                "已取消 CloudCLI 任务" in cancel_text or "已经是" in cancel_text,
                cancel_text,
            )
            return

        timeout_seconds = int(setting("run_wait", "120"))
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
        """可选真实 stop 测试：需要 stop_enabled=true，会向真实 CloudCLI 发送 abort-session。"""
        if not bool_setting("stop_enabled"):
            self.skipTest("Set stop_enabled=true in tests/config.yaml to send abort-session to real CloudCLI.")
        if not has_real_cloudcli_config():
            self.skipTest("Real /cloudcli stop needs CloudCLI credentials.")

        await self.command("/cloudcli session")
        session_ref = setting(("stop_session_ref", "stop_session_id", "session_id"), "1")
        provider = setting("stop_provider")
        command = f"/cloudcli stop {session_ref}"
        if provider:
            command += f" {provider}"

        stop_text = await self.command(command)
        self.assertIn("已向 CloudCLI 发送中止 session 请求", stop_text)


def extract_task_id(text: str) -> str:
    """从启动消息中的 `task=#N` 提取本地任务编号。"""
    match = re.search(r"task=#(\d+)", text)
    return match.group(1) if match else ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
