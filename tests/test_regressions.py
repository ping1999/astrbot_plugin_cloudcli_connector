from __future__ import annotations

import asyncio
import unittest

from authz import AuthorizationPolicy
from cloudcli_protocol import build_ws_url, parse_sse_event
from config import load_connector_settings
from identity import build_user_ref
from run_validation import is_safe_git_branch_name, looks_like_github_url
from state import UserRef


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


if __name__ == "__main__":
    unittest.main()
