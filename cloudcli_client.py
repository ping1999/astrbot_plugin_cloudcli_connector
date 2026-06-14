from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import aiohttp

try:
    from .cloudcli_protocol import (
        build_api_url,
        build_auth_headers,
        build_ws_url,
        iter_sse,
        redact_error_text,
    )
    from .state import PendingApproval
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli_protocol import (
        build_api_url,
        build_auth_headers,
        build_ws_url,
        iter_sse,
        redact_error_text,
    )
    from state import PendingApproval


logger = logging.getLogger(__name__)


class CloudCLIError(RuntimeError):
    pass


class CloudCLITimeout(CloudCLIError):
    pass


@dataclass
class CloudCLIConfig:
    base_url: str
    jwt_token: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    allow_unauthenticated_ws: bool = False
    timeout_seconds: int = 8
    agent_idle_timeout_seconds: int = 120


WaiterPredicate = Callable[[dict[str, Any]], bool]
PermissionCallback = Callable[[PendingApproval], Awaitable[None]]


class CloudCLIClient:
    def __init__(
        self,
        config: CloudCLIConfig,
        on_permission_request: PermissionCallback,
    ) -> None:
        self.config = config
        self._on_permission_request = on_permission_request
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._reader_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._waiters: list[tuple[WaiterPredicate, asyncio.Future]] = []
        self._cached_token = config.jwt_token.strip()

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._ws = None
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._fail_waiters(CloudCLIError("CloudCLI connection closed."))

    async def ensure_connected(self) -> None:
        async with self._connect_lock:
            if self._ws and not self._ws.closed:
                return
            await self._connect_locked()

    async def get_active_sessions(self) -> dict[str, Any]:
        await self.ensure_connected()
        response = await self._request(
            {"type": "get-active-sessions"},
            lambda item: item.get("type") == "active-sessions",
        )
        return response

    async def health_check(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "base_url": self.config.base_url.rstrip("/"),
            "auth": {"ok": False, "message": ""},
            "websocket": {"ok": False, "message": ""},
            "rest": {"ok": False, "message": ""},
            "agent": {"ok": bool(self.config.api_key), "message": ""},
        }

        try:
            await self._ensure_http_session()
            token = await self._get_token()
            if token:
                result["auth"] = {"ok": True, "message": "JWT 已可用。"}
            else:
                result["auth"] = {"ok": True, "message": "未返回 token，但配置允许继续尝试。"}
        except CloudCLIError as exc:
            if self.config.allow_unauthenticated_ws:
                result["auth"] = {"ok": True, "message": f"REST 未认证；WebSocket 允许匿名连接：{exc}"}
            else:
                result["auth"] = {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            result["auth"] = {"ok": False, "message": f"认证检查失败：{exc}"}

        try:
            await self.ensure_connected()
            result["websocket"] = {"ok": True, "message": "WebSocket 已连接。"}
        except CloudCLIError as exc:
            result["websocket"] = {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            result["websocket"] = {"ok": False, "message": f"WebSocket 检查失败：{exc}"}

        try:
            sessions = await self.get_recent_sessions(1)
            result["rest"] = {
                "ok": True,
                "message": f"REST 已可用，最近 session 返回 {len(sessions)} 条。",
            }
        except CloudCLIError as exc:
            result["rest"] = {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            result["rest"] = {"ok": False, "message": f"REST 检查失败：{exc}"}

        if self.config.api_key:
            result["agent"]["message"] = "已配置 cloudcli_api_key；为避免启动真实任务，未主动调用 /api/agent。"
        else:
            result["agent"]["message"] = "未配置 cloudcli_api_key；/cloudcli run 可能会被 CloudCLI 拒绝。"
        return result

    async def get_recent_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        await self._ensure_http_session()
        token = await self._get_token(allow_anonymous=self.config.allow_unauthenticated_ws)
        headers = self._auth_headers(token)
        params = {
            "skipSynchronization": "false",
            "sessionsLimit": str(max(1, min(limit, 100))),
            "sessionsOffset": "0",
        }
        try:
            data = await self._get_json_with_auth_retry("/api/projects", params, headers)
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(f"读取 CloudCLI 最近 session 失败：{exc}") from exc

        return self._extract_recent_sessions(data, limit)

    async def get_session_messages(
        self,
        session_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        await self._ensure_http_session()
        token = await self._get_token()
        params: dict[str, str] = {}
        if limit >= 0:
            params["limit"] = str(max(0, min(limit, 100)))
            params["offset"] = str(max(0, offset))
        path = f"/api/providers/sessions/{quote(session_id, safe='')}/messages"
        try:
            data = await self._get_json_with_auth_retry(path, params, self._auth_headers(token))
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(f"读取 CloudCLI session 消息失败：{exc}") from exc

        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {
                "messages": data,
                "total": len(data),
                "hasMore": False,
                "offset": 0,
                "limit": len(data),
            }
        raise CloudCLIError("无法解析 CloudCLI session 消息响应。")

    async def stream_agent(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        request_payload = dict(payload)
        request_payload["stream"] = True

        timeout = aiohttp.ClientTimeout(
            total=None,
            sock_connect=max(3, self.config.timeout_seconds),
            sock_read=max(10, self.config.agent_idle_timeout_seconds),
        )
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    self._api_url("/api/agent"),
                    json=request_payload,
                    headers=headers,
                ) as response:
                    if response.status >= 400:
                        body = await response.text()
                        if response.status == 401 and not self.config.api_key:
                            raise CloudCLIError(
                                "CloudCLI agent API 认证失败：请在 cloudcli_api_key 填写 CloudCLI UI 生成的 API Key。"
                            )
                        raise CloudCLIError(
                            f"CloudCLI agent API 请求失败：HTTP {response.status} {_redact_text(body)}"
                        )

                    content_type = response.headers.get("Content-Type", "")
                    if "text/event-stream" not in content_type:
                        data = await response.json(content_type=None)
                        if isinstance(data, dict):
                            yield {"type": "response", "data": data}
                        else:
                            yield {"type": "response", "data": {"raw": data}}
                        return

                    async for item in iter_sse(response.content):
                        yield item
        except CloudCLIError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CloudCLIError(f"CloudCLI agent 任务执行失败：{_redact_text(str(exc))}") from exc

    async def get_pending_permissions(self, session_id: str) -> list[PendingApproval]:
        await self.ensure_connected()
        response = await self._request(
            {"type": "get-pending-permissions", "sessionId": session_id},
            lambda item: item.get("type") == "pending-permissions-response"
            and item.get("sessionId") == session_id,
        )

        raw_items = response.get("data")
        if not isinstance(raw_items, list):
            return []
        approvals: list[PendingApproval] = []
        for raw in raw_items:
            if isinstance(raw, dict):
                approval = PendingApproval.from_cloudcli(raw)
                if approval:
                    approvals.append(approval)
        return approvals

    async def send_permission_decision(
        self,
        request_id: str,
        allow: bool,
        message: str = "",
    ) -> None:
        await self.ensure_connected()
        payload: dict[str, Any] = {
            "type": "claude-permission-response",
            "requestId": request_id,
            "allow": allow,
        }
        if message:
            payload["message"] = message
        await self._send_json(payload)

    async def abort_session(self, session_id: str, provider: str = "") -> None:
        await self.ensure_connected()
        payload: dict[str, Any] = {
            "type": "abort-session",
            "sessionId": session_id,
        }
        if provider:
            payload["provider"] = provider
        await self._send_json(payload)

    async def _connect_locked(self) -> None:
        if self._ws and not self._ws.closed:
            return
        await self._ensure_http_session()

        token = await self._get_token()
        ws_url = self._ws_url(token)
        try:
            ws = await self._session.ws_connect(
                ws_url,
                heartbeat=25,
            )
            self._ws = ws
        except Exception as exc:  # noqa: BLE001
            if token and not self.config.jwt_token.strip() and self.config.username and self.config.password:
                await self._clear_cached_token()
                try:
                    token = await self._get_token()
                    ws = await self._session.ws_connect(
                        self._ws_url(token),
                        heartbeat=25,
                    )
                    self._ws = ws
                except Exception as retry_exc:  # noqa: BLE001
                    raise CloudCLIError(
                        f"无法连接 CloudCLI WebSocket，重新登录后仍失败：{_redact_text(str(retry_exc))}"
                    ) from retry_exc
                else:
                    self._reader_task = asyncio.create_task(self._reader_loop(ws))
                    return
            raise CloudCLIError(f"无法连接 CloudCLI WebSocket：{_redact_text(str(exc))}") from exc

        self._reader_task = asyncio.create_task(self._reader_loop(ws))

    async def _ensure_http_session(self) -> None:
        if self._session and self._session.closed:
            self._session = None
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=max(3, self.config.timeout_seconds))
            self._session = aiohttp.ClientSession(timeout=timeout)

    async def _get_token(self, *, allow_anonymous: bool = False) -> str:
        if self._cached_token:
            return self._cached_token
        if not self.config.username or not self.config.password:
            if allow_anonymous:
                return ""
            raise CloudCLIError("未配置 CloudCLI JWT token，也没有配置用户名/密码。")
        if self._session is None:
            raise CloudCLIError("CloudCLI HTTP session 未初始化。")

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        try:
            async with self._session.post(
                self._api_url("/api/auth/login"),
                json={
                    "username": self.config.username,
                    "password": self.config.password,
                },
                headers=headers,
            ) as response:
                raw_body = await response.text()
                try:
                    data = json.loads(raw_body) if raw_body else {}
                except json.JSONDecodeError:
                    data = raw_body
                if response.status >= 400:
                    raise CloudCLIError(
                        f"登录 CloudCLI 失败：HTTP {response.status} {_redact_text(raw_body)}"
                    )
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, CloudCLIError):
                raise
            raise CloudCLIError(f"登录 CloudCLI 失败：{_redact_text(str(exc))}") from exc

        if not isinstance(data, dict) or not data.get("token"):
            raise CloudCLIError(f"登录 CloudCLI 失败：{_redact_text(str(data))}")
        self._cached_token = str(data["token"])
        return self._cached_token

    async def _clear_cached_token(self) -> None:
        if not self.config.jwt_token.strip():
            self._cached_token = ""

    def _auth_headers(self, token: str) -> dict[str, str]:
        return build_auth_headers(token, self.config.api_key)

    async def _get_json_with_auth_retry(
        self,
        path: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> Any:
        data, unauthorized = await self._get_json(path, params, headers)
        if not unauthorized:
            return data
        if self.config.jwt_token.strip() or not (self.config.username and self.config.password):
            raise CloudCLIError("CloudCLI REST 认证失败，请检查 JWT token 或用户名/密码。")

        await self._clear_cached_token()
        token = await self._get_token()
        data, unauthorized = await self._get_json(path, params, self._auth_headers(token))
        if unauthorized:
            raise CloudCLIError("CloudCLI REST 认证失败，请检查用户名/密码。")
        return data

    async def _get_json(
        self,
        path: str,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> tuple[Any, bool]:
        async with self._session.get(  # type: ignore[union-attr]
            self._api_url(path),
            params=params,
            headers=headers,
        ) as response:
            if response.status == 401:
                return None, True
            if response.status >= 400:
                body = await response.text()
                raise CloudCLIError(f"CloudCLI REST 请求失败：HTTP {response.status} {_redact_text(body)}")
            return await response.json(content_type=None), False

    async def _request(
        self,
        payload: dict[str, Any],
        predicate: WaiterPredicate,
    ) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._waiters.append((predicate, future))
        try:
            await self._send_json(payload)
            return await asyncio.wait_for(
                future,
                timeout=max(2, self.config.timeout_seconds),
            )
        except asyncio.TimeoutError as exc:
            raise CloudCLITimeout("等待 CloudCLI 响应超时。") from exc
        finally:
            self._waiters = [
                (match, waiter)
                for match, waiter in self._waiters
                if waiter is not future
            ]

    async def _send_json(self, payload: dict[str, Any]) -> None:
        if not self._ws or self._ws.closed:
            raise CloudCLIError("CloudCLI WebSocket 未连接。")
        async with self._send_lock:
            await self._ws.send_json(payload)

    async def _reader_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        disconnect_error: CloudCLIError | None = None
        try:
            async for message in ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(message.data)
                    except json.JSONDecodeError:
                        logger.warning("Ignored invalid CloudCLI WS JSON message.")
                        continue
                    await self._handle_message(data)
                elif message.type in {
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSE,
                }:
                    disconnect_error = CloudCLIError("CloudCLI WebSocket 已断开。")
                    break
            if disconnect_error is None:
                disconnect_error = CloudCLIError("CloudCLI WebSocket 已断开。")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            disconnect_error = CloudCLIError(f"CloudCLI WS 读取失败：{_redact_text(str(exc))}")
        finally:
            if not ws.closed:
                await ws.close()
            if self._ws is ws:
                self._ws = None
                if disconnect_error is not None:
                    self._fail_waiters(disconnect_error)

    async def _handle_message(self, data: Any) -> None:
        if not isinstance(data, dict):
            return

        matched_waiters: list[asyncio.Future] = []
        for predicate, future in list(self._waiters):
            if future.done():
                continue
            try:
                if predicate(data):
                    future.set_result(data)
                    matched_waiters.append(future)
            except Exception as exc:  # noqa: BLE001
                future.set_exception(exc)
                matched_waiters.append(future)
        if matched_waiters:
            self._waiters = [
                (match, future)
                for match, future in self._waiters
                if future not in matched_waiters
            ]

        approval = self._extract_permission_request(data)
        if approval:
            try:
                await self._on_permission_request(approval)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to handle CloudCLI permission request: %s", exc)

    def _extract_permission_request(self, data: dict[str, Any]) -> PendingApproval | None:
        message_type = str(data.get("type") or data.get("kind") or "")
        if message_type not in {"permission_request", "permission-request"}:
            has_shape = data.get("requestId") and data.get("toolName") and data.get("sessionId")
            if not has_shape:
                return None
        return PendingApproval.from_cloudcli(data)

    def _fail_waiters(self, exc: Exception) -> None:
        for _, future in self._waiters:
            if not future.done():
                future.set_exception(exc)
        self._waiters = []

    def _api_url(self, path: str) -> str:
        return build_api_url(self.config.base_url, path)

    def _ws_url(self, token: str) -> str:
        return build_ws_url(self.config.base_url, token)

    def _extract_recent_sessions(self, data: Any, limit: int) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            projects = data.get("projects") or data.get("data") or data.get("items")
        else:
            projects = data
        if not isinstance(projects, list):
            raise CloudCLIError("无法解析 CloudCLI 最近 session 响应。")

        provider_fields = (
            ("claude", "sessions"),
            ("codex", "codexSessions"),
            ("cursor", "cursorSessions"),
            ("gemini", "geminiSessions"),
            ("opencode", "opencodeSessions"),
        )
        result: list[dict[str, Any]] = []
        for project in projects:
            if not isinstance(project, dict):
                continue
            project_name = (
                project.get("displayName")
                or project.get("name")
                or project.get("projectId")
                or project.get("path")
                or ""
            )
            project_path = project.get("fullPath") or project.get("path") or ""
            for provider, field_name in provider_fields:
                sessions = project.get(field_name)
                if not isinstance(sessions, list):
                    continue
                for session in sessions:
                    item = self._normalize_recent_session(
                        session,
                        provider,
                        str(project_name),
                        str(project_path),
                    )
                    if item:
                        result.append(item)

        result.sort(key=lambda item: str(item.get("lastActivity") or ""), reverse=True)
        return result[: max(1, min(limit, 100))]

    def _normalize_recent_session(
        self,
        session: Any,
        provider: str,
        project_name: str,
        project_path: str,
    ) -> dict[str, Any] | None:
        if isinstance(session, str):
            session_id = session
            summary = ""
            message_count = None
            last_activity = ""
        elif isinstance(session, dict):
            session_id = (
                session.get("id")
                or session.get("sessionId")
                or session.get("session_id")
                or session.get("conversationId")
            )
            summary = session.get("summary") or session.get("title") or ""
            message_count = session.get("messageCount") or session.get("message_count")
            last_activity = (
                session.get("lastActivity")
                or session.get("updatedAt")
                or session.get("createdAt")
                or ""
            )
        else:
            return None
        if not session_id:
            return None
        return {
            "provider": provider,
            "id": str(session_id),
            "summary": str(summary) if summary else "",
            "messageCount": message_count,
            "lastActivity": str(last_activity) if last_activity else "",
            "projectName": project_name,
            "projectPath": project_path,
        }


def _redact_text(value: str) -> str:
    return redact_error_text(value)
