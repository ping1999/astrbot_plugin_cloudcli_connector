from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from authz import AuthorizationPolicy
from cloudcli_client import CloudCLIClient, CloudCLIConfig
from cloudcli_protocol import build_ws_url, parse_sse_event
from config import load_connector_settings
from identity import build_user_ref
from run_requests import RunRequestBuilder
from run_validation import is_safe_git_branch_name, looks_like_github_url
from state import PendingApproval, PluginState, UserRef


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


class FakeSessions:
    def __init__(self, project_path: str) -> None:
        self.project_path = project_path

    async def infer_single_bound_session(self, user: UserRef) -> tuple[str, str | None]:
        return "sess-1", None

    async def resolve_session_ref(self, user: UserRef, ref: str) -> tuple[dict[str, str] | None, str | None]:
        return {
            "id": "sess-1",
            "provider": "codex",
            "projectPath": self.project_path,
        }, None

    async def session_usage_error(self, user: UserRef, session_id: str) -> str:
        return ""

    async def find_recent_session(self, session_id: str) -> dict[str, str] | None:
        return {
            "id": session_id,
            "provider": "codex",
            "projectPath": self.project_path,
        }


class RunRequestTests(unittest.TestCase):
    def test_run_rejects_mixed_targets(self) -> None:
        async def scenario() -> tuple[object | None, str | None]:
            settings = load_connector_settings(
                {
                    "run_require_admin": False,
                    "session_require_admin": False,
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
                        "run_require_admin": False,
                        "session_require_admin": False,
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


class StateTests(unittest.TestCase):
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


class CloudCLIClientTests(unittest.TestCase):
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

            async def ws_connect(self, url: str, heartbeat: int):
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


if __name__ == "__main__":
    unittest.main()
