from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from approvals.approval_notifications import ApprovalNotificationPolicy
from approvals.approval_service import ApprovalService
from cloudcli.cloudcli_client import CloudCLIClient, CloudCLIConfig, CloudCLIError
from cloudcli.cloudcli_protocol import build_ws_url, parse_sse_event
from cloudcli.cloudcli_transport import WebSocketRequestMux
from commands.command_parser import ParsedCommand
from commands.command_router import CommandRoute, CommandRouter
from commands.formatting import format_pending, format_run_tasks, format_session_overview
from core.config import load_connector_settings
from core.redaction import redact_exception_text
from persistence.state import PluginState
from persistence.state_models import PendingApproval, UserRef
from runs.run_requests import RunRequestBuilder
from security.authz import AuthorizationPolicy
from security.identity import build_user_ref
from security.run_validation import is_safe_git_branch_name, is_safe_model_name, looks_like_github_url


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


class ProtocolTests(unittest.TestCase):
    def test_ws_url_keeps_base_path_and_escapes_token(self) -> None:
        self.assertEqual(
            build_ws_url("https://example.com/cloudcli", "a b"),
            "wss://example.com/cloudcli/ws?token=a+b",
        )

    def test_parse_sse_event(self) -> None:
        self.assertEqual(
            parse_sse_event('event: status\ndata: {"message":"ok"}'),
            {"event": "status", "message": "ok"},
        )

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
        class TestClient(CloudCLIClient):
            def __init__(self) -> None:
                super().__init__(
                    CloudCLIConfig(
                        base_url="http://127.0.0.1:3001",
                        allow_unauthenticated_ws=True,
                    ),
                    on_permission_request=lambda _approval: asyncio.sleep(0),
                )
                self.allow_anonymous_values: list[bool] = []

            async def _ensure_http_session(self) -> None:
                return None

            async def _get_token(self, *, allow_anonymous: bool = False) -> str:
                self.allow_anonymous_values.append(allow_anonymous)
                return "token"

            async def _get_json_with_auth_retry(self, path, params, headers):
                return {"projects": []}

        async def scenario() -> list[bool]:
            client = TestClient()
            await client.get_recent_sessions(1)
            return client.allow_anonymous_values

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
