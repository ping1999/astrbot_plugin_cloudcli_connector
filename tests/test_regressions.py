from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from approvals.approval_notifications import ApprovalNotificationPolicy
from approvals.approval_service import ApprovalService
from cloudcli.cloudcli_auth import CloudCLIAuth
from cloudcli.cloudcli_client import CloudCLIClient, CloudCLIConfig, CloudCLIError
from cloudcli.cloudcli_agent import CloudCLIAgentClient
from cloudcli.cloudcli_rest import CloudCLIRestClient
import cloudcli.cloudcli_agent as cloudcli_agent_module
from cloudcli.cloudcli_models import active_sessions_contains
from cloudcli.cloudcli_protocol import build_ws_url, parse_sse_event
from cloudcli.cloudcli_transport import WebSocketRequestMux
from commands.command_parser import ParsedCommand, parse_command
from commands.command_router import CommandRoute, CommandRouter
from commands.formatting import (
    format_agent_start_message,
    format_agent_status,
    format_health_report,
    format_pending,
    format_run_tasks,
    format_session_overview,
)
from commands.handlers import CloudCLICommandHandlers
from core.config import load_connector_settings
from core.redaction import redact_exception_text
from persistence.state import PluginState
from persistence.state_models import PendingApproval, UserRef
from runs.run_requests import RunRequestBuilder
from security.authz import AuthorizationPolicy
from security.identity import build_user_ref
from security.run_validation import is_safe_git_branch_name, is_safe_model_name, looks_like_github_url
from sessions.session_resolver import SessionResolver


class ValidationTests(unittest.TestCase):
    def test_github_url_accepts_standard_repo_urls(self) -> None:
        self.assertTrue(looks_like_github_url("https://github.com/user/repo"))
        self.assertTrue(looks_like_github_url("https://github.com/user/repo.git"))
        self.assertTrue(looks_like_github_url("git@github.com:user/repo.git"))

    def test_github_url_rejects_argument_shaped_values(self) -> None:
        self.assertFalse(looks_like_github_url("https://github.com/user/repo --upload-pack=/tmp/x"))
        self.assertFalse(looks_like_github_url("git@github.com:user/repo.git -c core.sshCommand=bad"))
        self.assertFalse(looks_like_github_url("https://github.com/user/repo?x=1"))
        self.assertFalse(looks_like_github_url("http://github.com/user/repo"))
        self.assertFalse(looks_like_github_url("https://evil.example/user/repo"))

    def test_branch_name_rejects_git_ref_edge_cases(self) -> None:
        self.assertTrue(is_safe_git_branch_name("feature/safe-name"))
        self.assertFalse(is_safe_git_branch_name("bad..branch"))
        self.assertFalse(is_safe_git_branch_name(".hidden/branch"))
        self.assertFalse(is_safe_git_branch_name("feature/.hidden"))
        self.assertFalse(is_safe_git_branch_name("feature.lock/branch"))
        self.assertFalse(is_safe_git_branch_name("feature/lock.lock"))

    def test_provider_boundary_values_reject_shell_metacharacters(self) -> None:
        for value in (
            "feature;calc",
            "feature$(whoami)",
            "feature`whoami`",
            "feature|cat",
            "feature&cat",
        ):
            self.assertFalse(is_safe_git_branch_name(value))
        for value in ("model;bad", "model$(bad)", "model`bad`", "model|bad"):
            self.assertFalse(is_safe_model_name(value))
        self.assertTrue(is_safe_model_name("claude-3.5-sonnet"))


class IdentityTests(unittest.TestCase):
    def test_async_admin_checker_is_awaited(self) -> None:
        class Event:
            unified_msg_origin = "origin"

            def get_platform_id(self) -> str:
                return "test"

            def get_sender_id(self) -> str:
                return "u1"

            def get_sender_name(self) -> str:
                return "User"

            async def is_admin(self) -> bool:
                return False

        user = asyncio.run(build_user_ref(Event()))
        self.assertTrue(user.identity_verified)
        self.assertFalse(user.is_admin)

    def test_missing_sender_id_is_not_privileged(self) -> None:
        class Event:
            unified_msg_origin = "platform:group:1"
            role = "admin"

            def get_platform_id(self) -> str:
                return "test"

            def get_sender_id(self) -> str:
                return ""

            def get_session_id(self) -> str:
                return "group-1"

        user = asyncio.run(build_user_ref(Event()))
        self.assertFalse(user.identity_verified)
        self.assertFalse(user.is_admin)

    def test_role_attribute_is_not_trusted_as_admin_source(self) -> None:
        class Event:
            unified_msg_origin = "origin"
            role = "admin"

            def get_platform_id(self) -> str:
                return "test"

            def get_sender_id(self) -> str:
                return "u1"

        user = asyncio.run(build_user_ref(Event()))
        self.assertTrue(user.identity_verified)
        self.assertFalse(user.is_admin)

    def test_async_sender_id_is_awaited(self) -> None:
        class Event:
            unified_msg_origin = "origin"

            async def get_platform_id(self) -> str:
                return "test"

            async def get_sender_id(self) -> str:
                return "u2"

            async def get_sender_name(self) -> str:
                return "Async User"

        user = asyncio.run(build_user_ref(Event()))
        self.assertEqual(user.user_key, "test:u2")
        self.assertEqual(user.display_name, "Async User")
        self.assertTrue(user.identity_verified)

    def test_missing_origin_uses_session_scoped_fallback(self) -> None:
        class Event:
            def __init__(self, session_id: str) -> None:
                self._session_id = session_id

            def get_platform_id(self) -> str:
                return "test"

            def get_sender_id(self) -> str:
                return "u1"

            def get_session_id(self) -> str:
                return self._session_id

        first = asyncio.run(build_user_ref(Event("group-1")))
        second = asyncio.run(build_user_ref(Event("group-2")))

        self.assertTrue(first.identity_verified)
        self.assertTrue(first.unified_msg_origin.startswith("test:fallback:"))
        self.assertNotEqual(first.unified_msg_origin, second.unified_msg_origin)

    def test_display_name_is_single_line(self) -> None:
        class Event:
            unified_msg_origin = "origin"

            def get_platform_id(self) -> str:
                return "test"

            def get_sender_id(self) -> str:
                return "u3"

            def get_sender_name(self) -> str:
                return "Alice\nAstrBot 管理员：是"

        user = asyncio.run(build_user_ref(Event()))
        self.assertEqual(user.display_name, "Alice AstrBot 管理员：是")

    def test_authorization_fails_closed_for_unverified_identity(self) -> None:
        settings = load_connector_settings(
            {
                "session_require_admin": False,
                "run_require_admin": False,
                "approval_require_admin": False,
                "session_access_mode": "authenticated",
                "run_access_mode": "authenticated",
                "approval_access_mode": "authenticated",
            }
        )
        authz = AuthorizationPolicy(settings)
        user = UserRef(
            user_key="test:unidentified",
            display_name="unknown",
            unified_msg_origin="origin",
            identity_verified=False,
        )
        self.assertFalse(authz.can_access_sessions(user).allowed)
        self.assertFalse(authz.can_run_agent(user).allowed)
        self.assertFalse(authz.can_manage_approvals(user).allowed)

    def test_legacy_require_admin_false_is_allowlist_only(self) -> None:
        settings = load_connector_settings(
            {
                "session_require_admin": False,
                "run_require_admin": False,
                "approval_require_admin": False,
            }
        )
        authz = AuthorizationPolicy(settings)
        user = UserRef("test:u1", "User", "origin")

        self.assertFalse(authz.can_access_sessions(user).allowed)
        self.assertFalse(authz.can_run_agent(user).allowed)
        self.assertFalse(authz.can_manage_approvals(user).allowed)

    def test_stop_permission_is_not_inherited_from_authenticated_session_access(self) -> None:
        settings = load_connector_settings({"session_access_mode": "authenticated"})
        authz = AuthorizationPolicy(settings)
        user = UserRef("test:u1", "User", "origin")

        self.assertTrue(authz.can_access_sessions(user).allowed)
        self.assertFalse(authz.can_stop_sessions(user).allowed)

        allowed = load_connector_settings(
            {
                "session_access_mode": "authenticated",
                "stop_allowed_user_keys": "test:u1",
            }
        )
        self.assertTrue(AuthorizationPolicy(allowed).can_stop_sessions(user).allowed)

    def test_approval_allowlist_can_bind_without_session_read_access(self) -> None:
        settings = load_connector_settings(
            {
                "session_require_admin": True,
                "approval_require_admin": True,
                "approval_allowed_user_keys": "test:u1",
            }
        )
        authz = AuthorizationPolicy(settings)
        user = UserRef("test:u1", "User", "origin")

        self.assertFalse(authz.can_access_sessions(user).allowed)
        self.assertFalse(authz.can_use_direct_session_id(user).allowed)
        self.assertTrue(authz.can_manage_approvals(user).allowed)
        self.assertTrue(authz.can_bind_sessions(user).allowed)
        self.assertFalse(authz.can_bind_direct_session_for_approval(user).allowed)

    def test_approval_direct_bind_requires_explicit_flag(self) -> None:
        settings = load_connector_settings(
            {
                "session_require_admin": True,
                "approval_require_admin": True,
                "approval_allowed_user_keys": "test:u1",
                "approval_allow_direct_session_bind": True,
            }
        )
        authz = AuthorizationPolicy(settings)
        user = UserRef("test:u1", "User", "origin")

        self.assertTrue(authz.can_bind_direct_session_for_approval(user).allowed)

    def test_approval_allowlist_cannot_bind_cached_index_without_direct_flag(self) -> None:
        class FakeClient:
            async def get_recent_sessions(self, limit: int = 100) -> list[dict[str, str]]:
                return []

        async def scenario() -> tuple[str, str, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings(
                    {
                        "session_require_admin": True,
                        "approval_require_admin": True,
                        "approval_allowed_user_keys": "test:u1",
                    }
                )
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.remember_session_index(
                    user,
                    [{"id": "sess-1", "provider": "codex", "projectPath": "C:/repo"}],
                )
                resolver = SessionResolver(
                    settings=settings,
                    authz=AuthorizationPolicy(settings),
                    state=state,
                    client=FakeClient(),
                )
                blocked = await resolver.direct_bind_error(user, "1")
                raw_cached_blocked = await resolver.direct_bind_error(user, "sess-1")

                allowed_settings = load_connector_settings(
                    {
                        "session_require_admin": True,
                        "approval_require_admin": True,
                        "approval_allowed_user_keys": "test:u1",
                        "approval_allow_direct_session_bind": True,
                    }
                )
                allowed_resolver = SessionResolver(
                    settings=allowed_settings,
                    authz=AuthorizationPolicy(allowed_settings),
                    state=state,
                    client=FakeClient(),
                )
                allowed = await allowed_resolver.direct_bind_error(user, "1")
                return blocked, raw_cached_blocked, allowed

        blocked, raw_cached_blocked, allowed = asyncio.run(scenario())
        self.assertIn("不能直接使用未绑定的 sessionId", blocked)
        self.assertIn("不能直接使用未绑定的 sessionId", raw_cached_blocked)
        self.assertEqual("", allowed)


class ConfigTests(unittest.TestCase):
    def test_base_url_strips_userinfo_and_health_report_redacts(self) -> None:
        settings = load_connector_settings(
            {"cloudcli_base_url": "http://user:pass@example.com:3001/cloudcli"}
        )
        self.assertEqual("http://example.com:3001/cloudcli", settings.cloudcli.base_url)

        rendered = format_health_report(
            {
                "base_url": "http://user:pass@example.com:3001/cloudcli",
                "auth": {"ok": True, "message": ""},
            }
        )
        self.assertNotIn("user:pass", rendered)

    def test_plain_http_with_credentials_is_limited_to_loopback(self) -> None:
        remote = load_connector_settings(
            {
                "cloudcli_base_url": "http://example.com:3001/cloudcli",
                "cloudcli_api_key": "secret",
            }
        )
        local = load_connector_settings(
            {
                "cloudcli_base_url": "http://localhost:3001/cloudcli",
                "cloudcli_api_key": "secret",
            }
        )

        self.assertEqual("http://127.0.0.1:3001", remote.cloudcli.base_url)
        self.assertEqual("http://localhost:3001/cloudcli", local.cloudcli.base_url)


class ProtocolTests(unittest.TestCase):
    def test_ws_url_keeps_base_path_without_query_token(self) -> None:
        self.assertEqual(
            build_ws_url("https://example.com/cloudcli", "a b"),
            "wss://example.com/cloudcli/ws",
        )

    def test_parse_sse_event(self) -> None:
        self.assertEqual(
            parse_sse_event('event: status\ndata: {"message":"ok"}'),
            {"event": "status", "message": "ok"},
        )

    def test_active_session_lookup_handles_provider_scoped_shapes(self) -> None:
        payload = {
            "sessions": {
                "claude": [
                    "sess-1",
                    {"sessionId": "sess-2"},
                    {"nested": {"conversationId": "sess-3"}},
                ],
                "codex": [{"id": "sess-4"}],
            }
        }
        self.assertTrue(active_sessions_contains(payload, "sess-1"))
        self.assertTrue(active_sessions_contains(payload, "sess-3", "claude"))
        self.assertFalse(active_sessions_contains(payload, "sess-3", "codex"))
        self.assertTrue(active_sessions_contains(payload, "sess-4", "codex"))

    def test_request_mux_serializes_same_key_requests(self) -> None:
        async def scenario() -> tuple[int, dict[str, object], dict[str, object]]:
            mux = WebSocketRequestMux()
            sent: list[dict[str, object]] = []

            async def send_json(payload: dict[str, object]) -> None:
                sent.append(payload)

            first = asyncio.create_task(
                mux.request(
                    payload={"n": 1},
                    predicate=lambda item: item.get("type") == "reply",
                    send_json=send_json,
                    timeout_seconds=5,
                    request_key="same",
                )
            )
            await asyncio.sleep(0)
            second = asyncio.create_task(
                mux.request(
                    payload={"n": 2},
                    predicate=lambda item: item.get("type") == "reply",
                    send_json=send_json,
                    timeout_seconds=5,
                    request_key="same",
                )
            )
            await asyncio.sleep(0)
            sent_before_reply = len(sent)
            await mux.handle_message({"type": "reply", "value": 1})
            first_result = await first
            await asyncio.sleep(0)
            await mux.handle_message({"type": "reply", "value": 2})
            second_result = await second
            return sent_before_reply, first_result, second_result

        sent_before_reply, first_result, second_result = asyncio.run(scenario())
        self.assertEqual(1, sent_before_reply)
        self.assertEqual(1, first_result["value"])
        self.assertEqual(2, second_result["value"])

    def test_request_mux_cleans_up_request_locks(self) -> None:
        async def scenario() -> int:
            mux = WebSocketRequestMux()

            async def send_json(payload: dict[str, object]) -> None:
                await mux.handle_message({"type": "response", "key": payload["key"]})

            for index in range(20):
                await mux.request(
                    payload={"key": f"request-{index}"},
                    predicate=lambda item, key=f"request-{index}": item.get("key") == key,
                    send_json=send_json,
                    timeout_seconds=1,
                    request_key=f"pending-permissions:session-{index}",
                )
            return len(mux._request_locks)

        self.assertEqual(0, asyncio.run(scenario()))


class CommandRouterTests(unittest.TestCase):
    def test_no_arg_route_rejects_extra_args(self) -> None:
        async def handler(user: UserRef, args: list[str]) -> str:
            return "ok"

        async def scenario() -> str:
            router = CommandRouter(
                help_text="help",
                routes={
                    "status": CommandRoute(
                        handler=handler,
                        usage="用法：/cloudcli status",
                        no_args=True,
                    )
                },
            )
            return await router.dispatch(
                ParsedCommand("status", ["extra"], ""),
                UserRef("test:u1", "User", "origin"),
            )

        self.assertEqual("用法：/cloudcli status", asyncio.run(scenario()))

    def test_unknown_route_returns_help(self) -> None:
        async def scenario() -> str:
            router = CommandRouter(help_text="help text", routes={})
            return await router.dispatch(
                ParsedCommand("missing", [], ""),
                UserRef("test:u1", "User", "origin"),
            )

        self.assertIn("help text", asyncio.run(scenario()))


class CommandHandlerTests(unittest.TestCase):
    def test_run_control_does_not_require_current_new_run_permission(self) -> None:
        class FakeRunService:
            called = False

            async def handle_run_control(self, user: UserRef, args: list[str]) -> str:
                self.called = True
                return "control"

            async def handle_run(self, user: UserRef, args: list[str]) -> str:
                self.called = True
                return "run"

        async def scenario() -> tuple[str, bool]:
            settings = load_connector_settings({"run_access_mode": "allowlist_only"})
            run_service = FakeRunService()
            handlers = CloudCLICommandHandlers(
                settings=settings,
                authz=AuthorizationPolicy(settings),
                state=object(),  # type: ignore[arg-type]
                client=object(),  # type: ignore[arg-type]
                session_resolver=object(),  # type: ignore[arg-type]
                run_service=run_service,  # type: ignore[arg-type]
                approval_service=object(),  # type: ignore[arg-type]
            )
            result = await handlers.handle_run(
                UserRef("test:u1", "User", "origin"),
                ["list"],
            )
            return result, run_service.called

        result, called = asyncio.run(scenario())
        self.assertEqual("control", result)
        self.assertTrue(called)

    def test_starting_run_still_requires_current_run_permission(self) -> None:
        class FakeRunService:
            called = False

            async def handle_run_control(self, user: UserRef, args: list[str]) -> str:
                self.called = True
                return "control"

            async def handle_run(self, user: UserRef, args: list[str]) -> str:
                self.called = True
                return "run"

        async def scenario() -> tuple[str, bool]:
            settings = load_connector_settings({"run_access_mode": "allowlist_only"})
            run_service = FakeRunService()
            handlers = CloudCLICommandHandlers(
                settings=settings,
                authz=AuthorizationPolicy(settings),
                state=object(),  # type: ignore[arg-type]
                client=object(),  # type: ignore[arg-type]
                session_resolver=object(),  # type: ignore[arg-type]
                run_service=run_service,  # type: ignore[arg-type]
                approval_service=object(),  # type: ignore[arg-type]
            )
            result = await handlers.handle_run(
                UserRef("test:u1", "User", "origin"),
                ["do", "work"],
            )
            return result, run_service.called

        result, called = asyncio.run(scenario())
        self.assertIn("CloudCLI agent", result)
        self.assertFalse(called)


class FakeSessions:
    def __init__(self, project_path: str, provider: str = "codex") -> None:
        self.project_path = project_path
        self.provider = provider

    async def infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        return "sess-1", None

    async def resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        return {
            "id": "sess-1",
            "provider": self.provider,
            "projectPath": self.project_path,
        }, None

    async def session_usage_error(self, user: UserRef, session_id: str) -> str:
        return ""

    async def find_recent_session(self, session_id: str) -> dict[str, str] | None:
        return {
            "id": session_id,
            "provider": self.provider,
            "projectPath": self.project_path,
        }


class RunRequestTests(unittest.TestCase):
    def test_run_rejects_mixed_targets(self) -> None:
        async def scenario() -> tuple[object | None, str | None]:
            settings = load_connector_settings(
                    {
                        "run_access_mode": "authenticated",
                        "session_access_mode": "authenticated",
                        "allowed_project_roots": "C:/allowed",
                    }
            )
            builder = RunRequestBuilder(
                settings=settings,
                authz=AuthorizationPolicy(settings),
                sessions=FakeSessions("C:/outside"),
            )
            return await builder.parse(
                UserRef("test:u1", "User", "origin"),
                ["--session", "sess-1", "--project", "C:/allowed/repo", "doit"],
            )

        parsed, error = asyncio.run(scenario())
        self.assertIsNone(parsed)
        self.assertIn("不能同时使用", error or "")

    def test_run_project_target_sends_authorized_absolute_path(self) -> None:
        async def scenario() -> tuple[str, str, str | None]:
            original_cwd = Path.cwd()
            with tempfile.TemporaryDirectory() as temp_dir:
                project = Path(temp_dir) / "repo"
                project.mkdir()
                try:
                    os.chdir(project)
                    settings = load_connector_settings(
                        {
                            "run_access_mode": "authenticated",
                            "allowed_project_roots": ".",
                        }
                    )
                    builder = RunRequestBuilder(
                        settings=settings,
                        authz=AuthorizationPolicy(settings),
                        sessions=FakeSessions("unused"),
                    )
                    parsed, error = await builder.parse(
                        UserRef("test:u1", "User", "origin"),
                        ["--project", ".", "doit"],
                    )
                    return (
                        "" if parsed is None else str(parsed.payload.get("projectPath") or ""),
                        str(project.resolve(strict=False)),
                        error,
                    )
                finally:
                    os.chdir(original_cwd)

        project_path, expected_path, error = asyncio.run(scenario())
        self.assertIsNone(error)
        self.assertEqual(os.path.normcase(expected_path), os.path.normcase(project_path))

    def test_run_parser_preserves_raw_message_after_double_dash(self) -> None:
        async def scenario() -> tuple[dict[str, object] | None, str | None, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                project = Path(temp_dir) / "repo with spaces"
                project.mkdir()
                settings = load_connector_settings(
                    {
                        "run_access_mode": "authenticated",
                        "allowed_project_roots": str(Path(temp_dir)),
                    }
                )
                builder = RunRequestBuilder(
                    settings=settings,
                    authz=AuthorizationPolicy(settings),
                    sessions=FakeSessions("unused"),
                )
                command = parse_command(
                    f'/cloudcli run --project="{project}" -- Say "hello world" exactly and "keep open'
                )
                parsed, error = await builder.parse(
                    UserRef("test:u1", "User", "origin"),
                    command.args,
                    raw_args=command.raw_args,
                )
                return None if parsed is None else parsed.payload, error, str(project.resolve(strict=False))

        payload, error, expected_project = asyncio.run(scenario())
        self.assertIsNone(error)
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual("Say \"hello world\" exactly and \"keep open", payload["message"])
        self.assertEqual(os.path.normcase(expected_project), os.path.normcase(str(payload["projectPath"])))

    def test_run_session_target_validates_resolved_project_path(self) -> None:
        async def scenario() -> tuple[object | None, str | None]:
            with tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                allowed = base / "allowed"
                outside = base / "outside"
                allowed.mkdir()
                outside.mkdir()
                settings = load_connector_settings(
                        {
                            "run_access_mode": "authenticated",
                            "session_access_mode": "authenticated",
                            "allowed_project_roots": str(allowed),
                        }
                )
                builder = RunRequestBuilder(
                    settings=settings,
                    authz=AuthorizationPolicy(settings),
                    sessions=FakeSessions(str(outside / "repo")),
                )
                return await builder.parse(
                    UserRef("test:u1", "User", "origin"),
                    ["--session", "sess-1", "doit"],
                )

        parsed, error = asyncio.run(scenario())
        self.assertIsNone(parsed)
        self.assertIn("projectPath 不在 allowed_project_roots", error or "")

    def test_run_session_target_keeps_opencode_provider(self) -> None:
        async def scenario() -> tuple[object | None, str | None]:
            with tempfile.TemporaryDirectory() as temp_dir:
                allowed = Path(temp_dir)
                settings = load_connector_settings(
                        {
                            "run_access_mode": "authenticated",
                            "session_access_mode": "authenticated",
                            "allowed_project_roots": str(allowed),
                        }
                )
                builder = RunRequestBuilder(
                    settings=settings,
                    authz=AuthorizationPolicy(settings),
                    sessions=FakeSessions(str(allowed / "repo"), provider="opencode"),
                )
                return await builder.parse(
                    UserRef("test:u1", "User", "origin"),
                    ["--session", "sess-1", "doit"],
                )

        parsed, error = asyncio.run(scenario())
        self.assertIsNone(error)
        assert parsed is not None
        self.assertEqual("opencode", parsed.payload["provider"])


class FormattingTests(unittest.TestCase):
    def test_session_overview_is_clipped(self) -> None:
        rendered = format_session_overview(
            None,
            [
                {
                    "id": "sess-1",
                    "provider": "claude",
                    "projectName": "x" * 1000,
                    "summary": "y" * 1000,
                }
            ],
            text_limit=240,
        )
        self.assertLessEqual(len(rendered), 280)
        self.assertIn("已截断", rendered)

    def test_pending_list_is_clipped_after_all_items_are_rendered(self) -> None:
        rendered = format_pending(
            [
                PendingApproval(f"request-{index}", "sess-1", "Tool", {"text": "x" * 1000})
                for index in range(20)
            ],
            300,
        )
        self.assertLessEqual(len(rendered), 380)
        self.assertIn("已截断", rendered)

    def test_run_task_list_is_clipped(self) -> None:
        rendered = format_run_tasks(
            [
                {
                    "id": str(index),
                    "status": "completed",
                    "provider": "codex",
                    "target": "C:/repo/" + ("x" * 500),
                }
                for index in range(20)
            ],
            20,
            300,
        )
        self.assertLessEqual(len(rendered), 380)
        self.assertIn("已截断", rendered)

    def test_agent_start_and_status_messages_are_clipped(self) -> None:
        start = format_agent_start_message(
            {"provider": "codex", "projectPath": "C:/repo/" + ("x" * 1000)},
            "1",
            240,
        )
        status = format_agent_status(
            {"type": "github-branch", "branch": {"name": "x" * 1000}},
            240,
        )

        self.assertLessEqual(len(start), 320)
        self.assertLessEqual(len(status), 320)
        self.assertIn("已截断", start)
        self.assertIn("已截断", status)


class StateTests(unittest.TestCase):
    def test_legacy_single_origin_state_migrates_to_scoped_data(self) -> None:
        async def scenario() -> tuple[list[str], bool]:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                path.write_text(
                    json.dumps(
                        {
                            "version": 2,
                            "users": {
                                "test:u1": {
                                    "origins": ["origin"],
                                    "bindings": ["sess-1"],
                                    "session_index": [
                                        {
                                            "id": "sess-1",
                                            "provider": "codex",
                                            "projectPath": "C:/repo",
                                        }
                                    ],
                                    "session_index_at": 1,
                                }
                            },
                            "pending": {},
                            "runs": {},
                            "audit": [],
                            "next_run_id": 1,
                        }
                    ),
                    encoding="utf-8",
                )
                state = PluginState(path)
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                indexed = await state.find_session_index_item(user, "sess-1")
                return await state.list_bindings(user), indexed is not None

        bindings, has_index = asyncio.run(scenario())
        self.assertEqual(["sess-1"], bindings)
        self.assertTrue(has_index)

    def test_bindings_pending_runs_and_audit_are_origin_scoped(self) -> None:
        async def scenario() -> tuple[list[str], int, int, int, bool]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                private_user = UserRef("test:u1", "User", "private-origin")
                group_user = UserRef("test:u1", "User", "group-origin")
                await state.bind_session(private_user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                await state.create_run_task(
                    private_user,
                    {"provider": "codex", "projectPath": "C:/repo", "message": "doit"},
                    "C:/repo",
                )
                await state.append_audit(
                    user=private_user,
                    action="allow",
                    approval=PendingApproval("request-2", "sess-1", "Tool", {}),
                )
                await state.remember_session_index(
                    private_user,
                    [{"id": "sess-1", "provider": "codex", "projectPath": "C:/repo"}],
                )
                indexed = await state.find_session_index_item(group_user, "sess-1")
                return (
                    await state.list_bindings(group_user),
                    len(await state.visible_pending_for_user(group_user, 10)),
                    len(await state.list_run_tasks(group_user, 10)),
                    len(await state.list_audit(group_user, 10)),
                    indexed is None,
                )

        bindings, pending_count, run_count, audit_count, index_isolated = asyncio.run(scenario())
        self.assertEqual([], bindings)
        self.assertEqual(0, pending_count)
        self.assertEqual(0, run_count)
        self.assertEqual(0, audit_count)
        self.assertTrue(index_isolated)

    def test_unbind_removes_only_current_origin_binding(self) -> None:
        async def scenario() -> tuple[list[str], list[str]]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                private_user = UserRef("test:u1", "User", "private-origin")
                group_user = UserRef("test:u1", "User", "group-origin")
                await state.bind_session(private_user, "sess-1", 10)
                await state.bind_session(group_user, "sess-1", 10)
                await state.unbind_session(group_user, "sess-1")
                return await state.list_bindings(private_user), await state.list_bindings(group_user)

        private_bindings, group_bindings = asyncio.run(scenario())
        self.assertEqual(["sess-1"], private_bindings)
        self.assertEqual([], group_bindings)

    def test_pending_input_redacts_common_secret_key_shapes(self) -> None:
        async def scenario() -> dict[str, object]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval(
                        "request-1",
                        "sess-1",
                        "Tool",
                        {
                            "openai_api_key": "sk-secret",
                            "githubToken": "ghp-secret",
                            "client_secret": "client-secret",
                            "private_key": "pem-secret",
                            "safe": "visible",
                        },
                    )
                )
                visible = await state.visible_pending_for_user(user, 10)
                return visible[0].input_data

        stored = asyncio.run(scenario())
        self.assertEqual("[redacted]", stored["openai_api_key"])
        self.assertEqual("[redacted]", stored["githubToken"])
        self.assertEqual("[redacted]", stored["client_secret"])
        self.assertEqual("[redacted]", stored["private_key"])
        self.assertEqual("visible", stored["safe"])

    def test_pending_claim_blocks_double_decision_and_preserves_refresh(self) -> None:
        async def scenario() -> tuple[bool, str, bool]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                approval = PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                await state.upsert_pending(approval)
                first, first_error = await state.claim_visible_request(user, None, 10, "allow")
                self.assertIsNone(first_error)
                await state.replace_pending_for_session("sess-1", [approval])
                second, second_error = await state.claim_visible_request(user, None, 10, "deny")
                await state.release_pending_claim("sess-1", "request-1", user.user_key)
                third, third_error = await state.claim_visible_request(user, None, 10, "deny")
                self.assertIsNone(third_error)
                return first is not None, second_error or "", third is not None

        first_claimed, second_error, third_claimed = asyncio.run(scenario())
        self.assertTrue(first_claimed)
        self.assertIn("正在被处理", second_error)
        self.assertTrue(third_claimed)

    def test_pending_upsert_preserves_active_claim(self) -> None:
        async def scenario() -> tuple[bool, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                first_user = UserRef("test:u1", "User 1", "origin-1")
                second_user = UserRef("test:u2", "User 2", "origin-2")
                await state.bind_session(first_user, "sess-1", 10)
                await state.bind_session(second_user, "sess-1", 10)
                approval = PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                await state.upsert_pending(approval)
                claimed, first_error = await state.claim_visible_request(first_user, None, 10, "allow")
                self.assertIsNone(first_error)
                self.assertIsNotNone(claimed)

                await state.upsert_pending(approval)
                second_claim, second_error = await state.claim_visible_request(second_user, None, 10, "deny")
                return second_claim is not None, second_error or ""

        second_claimed, second_error = asyncio.run(scenario())
        self.assertFalse(second_claimed)
        self.assertIn("正在被处理", second_error)

    def test_permission_request_tool_name_is_single_line(self) -> None:
        approval = PendingApproval.from_cloudcli(
            {
                "requestId": "request-1",
                "sessionId": "sess-1",
                "toolName": "Tool\nrequest: forged",
                "provider": "claude\nfake",
                "input": {},
            }
        )
        self.assertIsNotNone(approval)
        assert approval is not None
        self.assertEqual("Tool request: forged", approval.tool_name)
        self.assertEqual("claude fake", approval.provider)

    def test_stale_pending_claim_is_cleared_on_load(self) -> None:
        async def scenario() -> bool:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                state = PluginState(path)
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(PendingApproval("request-1", "sess-1", "Tool", {"value": 1}))
                await state.claim_visible_request(user, None, 10, "allow")

                reloaded = PluginState(path)
                await reloaded.load()
                claimed, error = await reloaded.claim_visible_request(user, None, 10, "deny")
                self.assertIsNone(error)
                return claimed is not None

        self.assertTrue(asyncio.run(scenario()))

    def test_loaded_legacy_sensitive_state_is_redacted(self) -> None:
        async def scenario() -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                path.write_text(
                    json.dumps(
                        {
                            "version": 3,
                            "users": {
                                "test:u1": {
                                    "origins": ["origin"],
                                    "bindings": ["sess-1"],
                                    "binding_origins": {"sess-1": ["origin"]},
                                }
                            },
                            "pending": {
                                "sess-1|request-1": {
                                    "request_id": "request-1",
                                    "session_id": "sess-1",
                                    "tool_name": "Tool",
                                    "input_data": {"api_key": "pending-secret"},
                                    "provider": "claude",
                                    "received_at": 1,
                                }
                            },
                            "runs": {
                                "1": {
                                    "id": "1",
                                    "user_key": "test:u1",
                                    "display_name": "User",
                                    "origin": "origin",
                                    "status": "completed",
                                    "provider": "codex",
                                    "target": "C:/repo",
                                    "message": "password=run-secret",
                                    "log": [{"ts": 1, "text": "token=log-secret"}],
                                    "summary": {"api_key": "summary-secret"},
                                }
                            },
                            "audit": [
                                {
                                    "ts": 1,
                                    "user_key": "test:u1",
                                    "display_name": "User",
                                    "origin": "origin",
                                    "action": "allow",
                                    "result": "failed: token=audit-secret",
                                    "request_id": "request-1",
                                    "session_id": "sess-1",
                                    "tool_name": "Tool",
                                    "provider": "claude",
                                    "input_summary": '{"password":"audit-input-secret"}',
                                }
                            ],
                            "next_run_id": 2,
                        }
                    ),
                    encoding="utf-8",
                )
                state = PluginState(path)
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                pending = await state.visible_pending_for_user(user, 10)
                run, error = await state.get_run_task(user, "1")
                self.assertIsNone(error)
                assert run is not None
                return pending[0].input_data, run, await state.list_audit(user, 10)

        pending_input, run, audit = asyncio.run(scenario())
        rendered = json.dumps(
            {"pending": pending_input, "run": run, "audit": audit},
            ensure_ascii=False,
        )
        self.assertNotIn("pending-secret", rendered)
        self.assertNotIn("run-secret", rendered)
        self.assertNotIn("log-secret", rendered)
        self.assertNotIn("summary-secret", rendered)
        self.assertNotIn("audit-secret", rendered)
        self.assertNotIn("audit-input-secret", rendered)

    def test_sensitive_state_details_are_not_persisted_by_default(self) -> None:
        async def scenario() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                state = PluginState(path)
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                approval = PendingApproval(
                    "request-1",
                    "sess-1",
                    "Tool",
                    {"plain": "bare-pending-secret"},
                )
                await state.upsert_pending(approval)
                await state.append_audit(user=user, action="allow", approval=approval)
                await state.create_run_task(
                    user,
                    {
                        "provider": "codex",
                        "projectPath": "C:/repo",
                        "message": "bare-run-secret",
                    },
                    "C:/repo",
                )
                visible = await state.visible_pending_for_user(user, 10)

                disk = json.loads(path.read_text(encoding="utf-8"))
                reloaded = PluginState(path)
                await reloaded.load()
                reloaded_visible = await reloaded.visible_pending_for_user(user, 10)
                return visible[0].input_data, disk, reloaded_visible[0].input_data

        memory_input, disk_state, reloaded_input = asyncio.run(scenario())
        self.assertIn("bare-pending-secret", json.dumps(memory_input, ensure_ascii=False))
        rendered_disk = json.dumps(disk_state, ensure_ascii=False)
        self.assertNotIn("bare-pending-secret", rendered_disk)
        self.assertNotIn("bare-run-secret", rendered_disk)
        self.assertIn("persist_sensitive_state=false", rendered_disk)
        self.assertNotIn("bare-pending-secret", json.dumps(reloaded_input, ensure_ascii=False))

    def test_session_index_omits_sensitive_display_fields_by_default(self) -> None:
        async def scenario() -> str:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                state = PluginState(path)
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.remember_user(user)
                await state.remember_session_index(
                    user,
                    [
                        {
                            "id": "sess-1",
                            "provider": "codex",
                            "projectName": "secret-project",
                            "projectPath": "C:/secret/repo",
                            "summary": "secret summary text",
                            "lastActivity": "2026-01-01T00:00:00Z",
                        }
                    ],
                )
                return path.read_text(encoding="utf-8")

        rendered = asyncio.run(scenario())
        self.assertIn("sess-1", rendered)
        self.assertIn("codex", rendered)
        self.assertNotIn("secret-project", rendered)
        self.assertNotIn("C:/secret/repo", rendered)
        self.assertNotIn("secret summary text", rendered)

    def test_run_event_updates_are_batched_until_flush(self) -> None:
        async def scenario() -> tuple[str, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "state.json"
                state = PluginState(path)
                state._save_batch_delay_seconds = 60
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                run_id = await state.create_run_task(
                    user,
                    {"provider": "codex", "projectPath": "C:/repo", "message": "doit"},
                    "C:/repo",
                )
                await state.update_run_task(run_id, event="assistant: streamed chunk")
                before_flush = path.read_text(encoding="utf-8")
                await state.flush()
                after_flush = path.read_text(encoding="utf-8")
                return before_flush, after_flush

        before_flush, after_flush = asyncio.run(scenario())
        self.assertNotIn("streamed chunk", before_flush)
        self.assertIn("streamed chunk", after_flush)

    def test_pending_request_ids_are_scoped_by_session(self) -> None:
        async def scenario() -> list[PendingApproval]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                await state.bind_session(user, "sess-2", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-2", "Tool", {"value": 2})
                )
                visible = await state.visible_pending_for_user(user, 10)
                await state.remove_pending("sess-1", "request-1")
                remaining = await state.visible_pending_for_user(user, 10)
                self.assertEqual({"sess-1", "sess-2"}, {item.session_id for item in visible})
                return remaining

        remaining = asyncio.run(scenario())
        self.assertEqual(["sess-2"], [item.session_id for item in remaining])

    def test_mark_interrupted_runs_on_startup(self) -> None:
        async def scenario() -> dict[str, object]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                run_id = await state.create_run_task(
                    user,
                    {"provider": "codex", "projectPath": "C:/repo", "message": "doit"},
                    "C:/repo",
                )
                changed = await state.mark_interrupted_runs("restart")
                task, error = await state.get_run_task(user, run_id)
                self.assertIsNone(error)
                assert task is not None
                task["changed"] = changed
                return task

        task = asyncio.run(scenario())
        self.assertEqual(1, task["changed"])
        self.assertEqual("interrupted", task["status"])
        self.assertTrue(task["finished_at"])

    def test_run_history_prunes_completed_tasks(self) -> None:
        async def scenario() -> list[str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                for index in range(5):
                    run_id = await state.create_run_task(
                        user,
                        {"provider": "codex", "projectPath": f"C:/repo-{index}", "message": "doit"},
                        f"C:/repo-{index}",
                        2,
                        10,
                    )
                    await state.update_run_task(run_id, status="completed", finished=True)
                    await state.prune_run_history(2, 10)
                return [str(item["id"]) for item in await state.list_run_tasks(user, 10)]

        self.assertEqual(["5", "4"], asyncio.run(scenario()))


class CloudCLIClientTests(unittest.TestCase):
    def test_agent_headers_include_jwt_and_api_key(self) -> None:
        async def scenario() -> dict[str, str]:
            client = CloudCLIClient(
                CloudCLIConfig(
                    base_url="http://127.0.0.1:3001",
                    jwt_token="jwt-token",
                    api_key="api-secret",
                ),
                on_permission_request=lambda _approval: asyncio.sleep(0),
            )
            return await client._agent_auth_headers()

        headers = asyncio.run(scenario())
        self.assertEqual("Bearer jwt-token", headers.get("Authorization"))
        self.assertEqual("api-secret", headers.get("X-API-Key"))

    def test_rest_refreshes_expired_static_jwt_when_login_credentials_exist(self) -> None:
        class FakeContent:
            def __init__(self, text: str) -> None:
                self.payload = text.encode("utf-8")

            async def iter_chunked(self, _size: int):
                yield self.payload

        class FakeResponse:
            def __init__(self, status: int, body: str = "") -> None:
                self.status = status
                self.content = FakeContent(body)
                self.charset = "utf-8"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def __init__(self) -> None:
                self.get_headers: list[dict[str, str]] = []
                self.login_payloads: list[dict[str, str]] = []

            def get(self, _url: str, *, params=None, headers=None, allow_redirects=None):
                self.get_headers.append(dict(headers or {}))
                if len(self.get_headers) == 1:
                    return FakeResponse(401)
                return FakeResponse(200, '{"projects": []}')

            def post(self, _url: str, *, json=None, headers=None, allow_redirects=None):
                self.login_payloads.append(dict(json or {}))
                return FakeResponse(200, '{"token": "fresh-token"}')

        async def scenario() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
            session = FakeSession()
            config = CloudCLIConfig(
                base_url="http://127.0.0.1:3001",
                jwt_token="expired-token",
                username="user",
                password="password",
            )

            async def ensure_session() -> FakeSession:
                return session

            auth = CloudCLIAuth(
                config=config,
                ensure_session=ensure_session,
                api_url=lambda path: f"http://127.0.0.1:3001{path}",
            )
            rest = CloudCLIRestClient(
                config=config,
                auth=auth,
                ensure_session=ensure_session,
                api_url=lambda path: f"http://127.0.0.1:3001{path}",
            )
            await rest.get_recent_sessions(1)
            return session.get_headers, session.login_payloads

        get_headers, login_payloads = asyncio.run(scenario())
        self.assertEqual("Bearer expired-token", get_headers[0].get("Authorization"))
        self.assertEqual("Bearer fresh-token", get_headers[1].get("Authorization"))
        self.assertEqual([{"username": "user", "password": "password"}], login_payloads)

    def test_rest_refuses_redirects_to_avoid_api_key_leak(self) -> None:
        class FakeContent:
            async def iter_chunked(self, _size: int):
                yield b""

        class FakeResponse:
            status = 302
            charset = "utf-8"
            headers = {"Location": "https://evil.example/steal?api_key=secret-value"}
            content = FakeContent()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def __init__(self) -> None:
                self.allow_redirects: list[object] = []

            def get(self, _url: str, *, params=None, headers=None, allow_redirects=None):
                self.allow_redirects.append(allow_redirects)
                return FakeResponse()

        async def scenario() -> tuple[list[object], str]:
            session = FakeSession()
            config = CloudCLIConfig(
                base_url="http://127.0.0.1:3001",
                jwt_token="jwt-token",
                api_key="api-secret",
            )

            async def ensure_session() -> FakeSession:
                return session

            rest = CloudCLIRestClient(
                config=config,
                auth=CloudCLIAuth(
                    config=config,
                    ensure_session=ensure_session,
                    api_url=lambda path: f"http://127.0.0.1:3001{path}",
                ),
                ensure_session=ensure_session,
                api_url=lambda path: f"http://127.0.0.1:3001{path}",
            )
            try:
                await rest.get_recent_sessions(1)
            except CloudCLIError as exc:
                return session.allow_redirects, str(exc)
            return session.allow_redirects, ""

        allow_redirects, error = asyncio.run(scenario())
        self.assertEqual([False], allow_redirects)
        self.assertIn("redirect refused", error)
        self.assertNotIn("secret-value", error)

    def test_login_refuses_redirects_to_avoid_api_key_leak(self) -> None:
        class FakeContent:
            async def iter_chunked(self, _size: int):
                yield b""

        class FakeResponse:
            status = 302
            charset = "utf-8"
            headers = {"Location": "https://evil.example/login?api_key=secret-value"}
            content = FakeContent()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def __init__(self) -> None:
                self.allow_redirects: list[object] = []

            def post(self, _url: str, *, json=None, headers=None, allow_redirects=None):
                self.allow_redirects.append(allow_redirects)
                return FakeResponse()

        async def scenario() -> tuple[list[object], str]:
            session = FakeSession()
            config = CloudCLIConfig(
                base_url="http://127.0.0.1:3001",
                username="user",
                password="password",
                api_key="api-secret",
            )
            auth = CloudCLIAuth(
                config=config,
                ensure_session=lambda: asyncio.sleep(0, result=session),
                api_url=lambda path: f"http://127.0.0.1:3001{path}",
            )
            try:
                await auth.get_token()
            except CloudCLIError as exc:
                return session.allow_redirects, str(exc)
            return session.allow_redirects, ""

        allow_redirects, error = asyncio.run(scenario())
        self.assertEqual([False], allow_redirects)
        self.assertIn("redirect refused", error)
        self.assertNotIn("secret-value", error)

    def test_agent_refuses_redirects_to_avoid_api_key_leak(self) -> None:
        class FakeContent:
            async def iter_chunked(self, _size: int):
                yield b""

        class FakeResponse:
            status = 302
            headers = {"Content-Type": "text/plain", "Location": "https://evil.example/agent?api_key=secret-value"}
            content = FakeContent()
            charset = "utf-8"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            allow_redirects: list[object] = []

            def __init__(self, *args, **kwargs) -> None:
                self.kwargs = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, _url: str, *, json=None, headers=None, allow_redirects=None):
                self.allow_redirects.append(allow_redirects)
                return FakeResponse()

        class FakeAuth:
            async def agent_headers(self) -> dict[str, str]:
                return {"X-API-Key": "api-secret"}

        async def scenario() -> tuple[list[object], str]:
            old_factory = cloudcli_agent_module.create_http_session
            try:
                FakeSession.allow_redirects = []
                cloudcli_agent_module.create_http_session = lambda _timeout: FakeSession()  # type: ignore[assignment]
                client = CloudCLIAgentClient(
                    config=CloudCLIConfig(
                        base_url="http://127.0.0.1:3001",
                        api_key="api-secret",
                    ),
                    auth=FakeAuth(),  # type: ignore[arg-type]
                    api_url=lambda path: f"http://127.0.0.1:3001{path}",
                )
                try:
                    _events = [event async for event in client.stream_agent({"message": "hi"})]
                except CloudCLIError as exc:
                    return FakeSession.allow_redirects, str(exc)
                return FakeSession.allow_redirects, ""
            finally:
                cloudcli_agent_module.create_http_session = old_factory  # type: ignore[assignment]

        allow_redirects, error = asyncio.run(scenario())
        self.assertEqual([False], allow_redirects)
        self.assertIn("redirect refused", error)
        self.assertNotIn("secret-value", error)

    def test_agent_stream_refreshes_expired_cached_login_token(self) -> None:
        class FakeContent:
            def __init__(self, text: str) -> None:
                self.payload = text.encode("utf-8")

            async def iter_chunked(self, _size: int):
                yield self.payload

        class FakeResponse:
            def __init__(self, status: int, body: str = "") -> None:
                self.status = status
                self.headers = {"Content-Type": "application/json"}
                self.content = FakeContent(body)
                self.charset = "utf-8"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            responses = [
                FakeResponse(401),
                FakeResponse(200, '{"success": true}'),
            ]
            sent_headers: list[dict[str, str]] = []

            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, _url: str, *, json=None, headers=None, allow_redirects=None):
                self.sent_headers.append(dict(headers or {}))
                return self.responses.pop(0)

        class FakeAuth:
            calls = 0
            cleared = 0

            async def agent_headers(self) -> dict[str, str]:
                self.calls += 1
                return {"Authorization": f"Bearer token-{self.calls}"}

            async def clear_cached_token(self, *, force: bool = False) -> None:
                self.force = force
                self.cleared += 1

        async def scenario() -> tuple[int, list[dict[str, str]], list[dict[str, object]]]:
            old_factory = cloudcli_agent_module.create_http_session
            auth = FakeAuth()
            try:
                cloudcli_agent_module.create_http_session = lambda _timeout: FakeSession()  # type: ignore[assignment]
                client = CloudCLIAgentClient(
                    config=CloudCLIConfig(
                        base_url="http://127.0.0.1:3001",
                        username="user",
                        password="password",
                    ),
                    auth=auth,  # type: ignore[arg-type]
                    api_url=lambda path: f"http://127.0.0.1:3001{path}",
                )
                events = [event async for event in client.stream_agent({"message": "hi"})]
                return auth.cleared, FakeSession.sent_headers, events
            finally:
                cloudcli_agent_module.create_http_session = old_factory  # type: ignore[assignment]

        cleared, sent_headers, events = asyncio.run(scenario())
        self.assertEqual(1, cleared)
        self.assertEqual(["Bearer token-1", "Bearer token-2"], [item["Authorization"] for item in sent_headers])
        self.assertEqual([{"type": "response", "data": {"success": True}}], events)

    def test_unauthenticated_ws_does_not_require_token(self) -> None:
        class FakeWebSocket:
            closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def close(self) -> None:
                self.closed = True

        class FakeSession:
            closed = False

            def __init__(self) -> None:
                self.connected_url = ""

            async def ws_connect(self, url: str, heartbeat: int, headers=None):
                self.connected_url = url
                return FakeWebSocket()

            async def close(self) -> None:
                self.closed = True

        class TestClient(CloudCLIClient):
            async def _ensure_http_session(self) -> None:
                if self._session is None:
                    self._session = FakeSession()  # type: ignore[assignment]

        async def scenario() -> str:
            client = TestClient(
                CloudCLIConfig(
                    base_url="http://127.0.0.1:3001",
                    allow_unauthenticated_ws=True,
                ),
                on_permission_request=lambda _approval: asyncio.sleep(0),
            )
            await client.ensure_connected()
            session = client._session
            await client.close()
            return getattr(session, "connected_url", "")

        self.assertEqual("ws://127.0.0.1:3001/ws", asyncio.run(scenario()))

    def test_websocket_connect_sends_api_key_header(self) -> None:
        class FakeWebSocket:
            closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def close(self) -> None:
                self.closed = True

        class FakeSession:
            closed = False

            def __init__(self) -> None:
                self.connected_headers: dict[str, str] = {}

            async def ws_connect(self, url: str, heartbeat: int, headers=None):
                self.connected_headers = dict(headers or {})
                return FakeWebSocket()

            async def close(self) -> None:
                self.closed = True

        class TestClient(CloudCLIClient):
            async def _ensure_http_session(self) -> None:
                if self._session is None:
                    self._session = FakeSession()  # type: ignore[assignment]

        async def scenario() -> dict[str, str]:
            client = TestClient(
                CloudCLIConfig(
                    base_url="http://127.0.0.1:3001",
                    jwt_token="jwt-token",
                    api_key="api-secret",
                ),
                on_permission_request=lambda _approval: asyncio.sleep(0),
            )
            await client.ensure_connected()
            session = client._session
            await client.close()
            return getattr(session, "connected_headers", {})

        headers = asyncio.run(scenario())
        self.assertEqual("Bearer jwt-token", headers.get("Authorization"))
        self.assertEqual("api-secret", headers.get("X-API-Key"))

    def test_recent_sessions_do_not_inherit_unauthenticated_ws_setting(self) -> None:
        async def scenario() -> list[bool]:
            client = CloudCLIClient(
                CloudCLIConfig(
                    base_url="http://127.0.0.1:3001",
                    allow_unauthenticated_ws=True,
                ),
                on_permission_request=lambda _approval: asyncio.sleep(0),
            )
            allow_anonymous_values: list[bool] = []

            async def get_token(*, allow_anonymous: bool = False) -> str:
                allow_anonymous_values.append(allow_anonymous)
                return "token"

            async def get_json_with_auth_retry(path, params, headers):
                return {"projects": []}

            client._rest.auth.get_token = get_token  # type: ignore[method-assign]
            client._rest._get_json_with_auth_retry = get_json_with_auth_retry  # type: ignore[method-assign]
            await client.get_recent_sessions(1)
            return allow_anonymous_values

        self.assertEqual([False], asyncio.run(scenario()))

    def test_supervisor_reconnects_after_websocket_disconnect(self) -> None:
        class FakeWebSocket:
            closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                await asyncio.sleep(0)
                raise StopAsyncIteration

            async def close(self) -> None:
                self.closed = True

            async def send_json(self, payload: dict[str, object]) -> None:
                return None

        class FakeSession:
            closed = False

            def __init__(self) -> None:
                self.connect_count = 0

            async def ws_connect(self, url: str, heartbeat: int, headers=None):
                self.connect_count += 1
                return FakeWebSocket()

            async def close(self) -> None:
                self.closed = True

        class TestClient(CloudCLIClient):
            reconnect_initial_seconds = 0.01
            reconnect_max_seconds = 0.02

            async def _ensure_http_session(self) -> None:
                if self._session is None:
                    self._session = FakeSession()  # type: ignore[assignment]

        async def scenario() -> int:
            client = TestClient(
                CloudCLIConfig(
                    base_url="http://127.0.0.1:3001",
                    allow_unauthenticated_ws=True,
                ),
                on_permission_request=lambda _approval: asyncio.sleep(0),
            )
            client.start(auto_connect=True)
            for _ in range(100):
                session = client._session
                if getattr(session, "connect_count", 0) >= 2:
                    break
                await asyncio.sleep(0.01)
            session = client._session
            count = getattr(session, "connect_count", 0)
            await client.close()
            return count

        self.assertGreaterEqual(asyncio.run(scenario()), 2)


class ApprovalServiceTests(unittest.TestCase):
    def test_legacy_approval_require_admin_false_does_not_push_to_everyone(self) -> None:
        policy = ApprovalNotificationPolicy(
            approval_allowed_user_keys=frozenset(),
            approval_require_admin=False,
            approval_access_mode="allowlist_only",
        )

        self.assertFalse(policy.can_receive_details("test:u1"))

    def test_decision_is_blocked_when_pending_refresh_fails(self) -> None:
        class FailingClient:
            decision_sent = False

            async def get_pending_permissions(self, session_id: str):
                raise CloudCLIError("temporary failure")

            async def send_permission_decision(self, *args, **kwargs) -> None:
                self.decision_sent = True

        async def scenario() -> tuple[str, bool]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings({})
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin", is_admin=True)
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                client = FailingClient()
                service = ApprovalService(
                    settings=settings,
                    state=state,
                    client=client,  # type: ignore[arg-type]
                    notifications=ApprovalNotificationPolicy(
                        approval_allowed_user_keys=frozenset(),
                        approval_require_admin=True,
                    ),
                    send_proactive=lambda _origin, _text: asyncio.sleep(0),
                    track_task=lambda _task: None,
                )
                result = await service.handle_allow(user, [])
                return result, client.decision_sent

        result, decision_sent = asyncio.run(scenario())
        self.assertIn("同步 CloudCLI 待审批权限失败", result)
        self.assertFalse(decision_sent)

    def test_allow_marks_pending_unconfirmed_when_confirmation_fails(self) -> None:
        class UnconfirmedClient:
            decision_count = 0

            async def get_pending_permissions(self, session_id: str):
                return [PendingApproval("request-1", session_id, "Tool", {"value": 1})]

            async def send_permission_decision(self, *args, **kwargs) -> None:
                self.decision_count += 1

        async def scenario() -> tuple[str, bool, bool, str, str, int]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings({})
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin", is_admin=True)
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                client = UnconfirmedClient()
                service = ApprovalService(
                    settings=settings,
                    state=state,
                    client=client,  # type: ignore[arg-type]
                    notifications=ApprovalNotificationPolicy(
                        approval_allowed_user_keys=frozenset(),
                        approval_require_admin=True,
                    ),
                    send_proactive=lambda _origin, _text: asyncio.sleep(0),
                    track_task=lambda _task: None,
                )
                service.decision_confirm_delay_seconds = 0
                result = await service.handle_allow(user, [])
                pending = await state.get_pending("sess-1", "request-1")
                claimed, error = await state.claim_visible_request(user, None, 10, "deny")
                deny_result = await service.handle_deny(user, ["changed-mind"])
                return (
                    result,
                    pending is not None,
                    claimed is not None and not error,
                    error or "",
                    deny_result,
                    client.decision_count,
                )

        result, still_pending, claimable, claim_error, deny_result, decision_count = asyncio.run(scenario())
        self.assertIn("尚未确认", result)
        self.assertTrue(still_pending)
        self.assertFalse(claimable)
        self.assertIn("尚未确认", claim_error)
        self.assertIn("尚未确认", deny_result)
        self.assertEqual(1, decision_count)

    def test_cancelled_allow_releases_pending_claim(self) -> None:
        class CancellingClient:
            async def get_pending_permissions(self, session_id: str):
                return [PendingApproval("request-1", session_id, "Tool", {"value": 1})]

            async def send_permission_decision(self, *args, **kwargs) -> None:
                raise asyncio.CancelledError()

        async def scenario() -> tuple[bool, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings({})
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin", is_admin=True)
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                service = ApprovalService(
                    settings=settings,
                    state=state,
                    client=CancellingClient(),  # type: ignore[arg-type]
                    notifications=ApprovalNotificationPolicy(
                        approval_allowed_user_keys=frozenset(),
                        approval_require_admin=True,
                    ),
                    send_proactive=lambda _origin, _text: asyncio.sleep(0),
                    track_task=lambda _task: None,
                )
                try:
                    await service.handle_allow(user, [])
                except asyncio.CancelledError:
                    pass
                claimed, error = await state.claim_visible_request(user, None, 10, "deny")
                return claimed is not None, error or ""

        claimed, error = asyncio.run(scenario())
        self.assertTrue(claimed)
        self.assertEqual("", error)

    def test_cancelled_timeout_worker_releases_pending_claim(self) -> None:
        async def scenario() -> tuple[bool, str]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings({"approval_allowed_user_keys": "test:u1"})
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )

                async def send_proactive(_origin: str, _text: str) -> None:
                    raise asyncio.CancelledError()

                service = ApprovalService(
                    settings=settings,
                    state=state,
                    client=object(),  # type: ignore[arg-type]
                    notifications=ApprovalNotificationPolicy(
                        approval_allowed_user_keys=frozenset({"test:u1"}),
                        approval_require_admin=True,
                    ),
                    send_proactive=send_proactive,
                    track_task=lambda _task: None,
                )
                try:
                    await service._timeout_worker("sess-1", "request-1", 0, 1)
                except asyncio.CancelledError:
                    pass
                claimed, error = await state.claim_visible_request(user, None, 10, "deny")
                return claimed is not None, error or ""

        claimed, error = asyncio.run(scenario())
        self.assertTrue(claimed)
        self.assertEqual("", error)

    def test_timeout_deny_retries_after_temporary_send_failure(self) -> None:
        class FlakyClient:
            attempts = 0

            async def send_permission_decision(self, *args, **kwargs) -> None:
                self.attempts += 1
                if self.attempts == 1:
                    raise CloudCLIError("temporary failure")

            async def get_pending_permissions(self, session_id: str):
                if self.attempts >= 2:
                    return []
                return [PendingApproval("request-1", session_id, "Tool", {"value": 1})]

        async def scenario() -> tuple[int, bool]:
            with tempfile.TemporaryDirectory() as temp_dir:
                settings = load_connector_settings(
                    {
                        "approval_timeout_action": "deny",
                        "approval_allowed_user_keys": "test:u1",
                    }
                )
                state = PluginState(Path(temp_dir) / "state.json")
                await state.load()
                user = UserRef("test:u1", "User", "origin")
                await state.bind_session(user, "sess-1", 10)
                await state.upsert_pending(
                    PendingApproval("request-1", "sess-1", "Tool", {"value": 1})
                )
                client = FlakyClient()
                service = ApprovalService(
                    settings=settings,
                    state=state,
                    client=client,  # type: ignore[arg-type]
                    notifications=ApprovalNotificationPolicy(
                        approval_allowed_user_keys=frozenset({"test:u1"}),
                        approval_require_admin=True,
                    ),
                    send_proactive=lambda _origin, _text: asyncio.sleep(0),
                    track_task=lambda _task: None,
                )
                service.timeout_deny_retry_initial_seconds = 0
                await service._timeout_worker("sess-1", "request-1", 0, 1)
                return client.attempts, await state.get_pending("sess-1", "request-1") is None

        attempts, removed = asyncio.run(scenario())
        self.assertEqual(2, attempts)
        self.assertTrue(removed)


class RedactionTests(unittest.TestCase):
    def test_exception_traceback_is_redacted(self) -> None:
        try:
            raise ValueError("client_secret=secret-value token=token-value")
        except ValueError as exc:
            rendered = redact_exception_text(exc)
        self.assertNotIn("secret-value", rendered)
        self.assertNotIn("token-value", rendered)


if __name__ == "__main__":
    unittest.main()
