"""CloudCLI 聚合客户端：封装认证、REST、WebSocket 和 Agent SSE 四类交互。"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import aiohttp

try:
    from .cloudcli_agent import CloudCLIAgentClient
    from .cloudcli_auth import CloudCLIAuth
    from .cloudcli_errors import CloudCLIError, CloudCLITimeout
    from .cloudcli_http import create_http_session
    from .cloudcli_models import AbortSessionResult, active_sessions_contains
    from .cloudcli_protocol import (
        MAX_WS_MESSAGE_CHARS,
        build_api_url,
        build_ws_url,
        redact_error_text,
    )
    from .cloudcli_rest import CloudCLIRestClient
    from .cloudcli_transport import WaiterPredicate, WebSocketRequestMux
    from ..persistence.state_models import PendingApproval
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from cloudcli.cloudcli_agent import CloudCLIAgentClient
    from cloudcli.cloudcli_auth import CloudCLIAuth
    from cloudcli.cloudcli_errors import CloudCLIError, CloudCLITimeout
    from cloudcli.cloudcli_http import create_http_session
    from cloudcli.cloudcli_models import AbortSessionResult, active_sessions_contains
    from cloudcli.cloudcli_protocol import (
        MAX_WS_MESSAGE_CHARS,
        build_api_url,
        build_ws_url,
        redact_error_text,
    )
    from cloudcli.cloudcli_rest import CloudCLIRestClient
    from cloudcli.cloudcli_transport import WaiterPredicate, WebSocketRequestMux
    from persistence.state_models import PendingApproval


logger = logging.getLogger(__name__)


@dataclass
class CloudCLIConfig:
    """CloudCLI 连接配置，由插件配置读取并做过安全归一化。"""

    base_url: str
    jwt_token: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    allow_unauthenticated_ws: bool = False
    timeout_seconds: int = 8
    agent_idle_timeout_seconds: int = 120


PermissionCallback = Callable[[PendingApproval], Awaitable[None]]


class CloudCLIClient:
    """面向业务层的 CloudCLI 客户端，隐藏底层协议和重连细节。"""

    reconnect_initial_seconds = 1.0
    reconnect_max_seconds = 30.0
    abort_confirm_attempts = 3
    abort_confirm_delay_seconds = 0.3

    def __init__(
        self,
        config: CloudCLIConfig,
        on_permission_request: PermissionCallback,
    ) -> None:
        """创建客户端状态和子客户端；此时还不会真正发起网络连接。"""
        self.config = config
        self._on_permission_request = on_permission_request
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._reader_task: asyncio.Task | None = None
        self._supervisor_task: asyncio.Task | None = None
        self._permission_worker_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._reconnect_event = asyncio.Event()
        self._reconnect_after_disconnect = False
        self._permission_queue: asyncio.Queue[PendingApproval] = asyncio.Queue(maxsize=256)
        self._closing = False
        self._mux = WebSocketRequestMux()
        self._auth = CloudCLIAuth(
            config=config,
            ensure_session=self._ensure_auth_http_session,
            api_url=self._api_url,
        )
        self._rest = CloudCLIRestClient(
            config=config,
            auth=self._auth,
            ensure_session=self._ensure_auth_http_session,
            api_url=self._api_url,
        )
        self._agent = CloudCLIAgentClient(
            config=config,
            auth=self._auth,
            api_url=self._api_url,
        )

    def start(self, *, auto_connect: bool = True) -> None:
        """启动权限请求派发 worker 和 WebSocket 重连监督任务。"""
        if not self._permission_worker_task or self._permission_worker_task.done():
            self._permission_worker_task = asyncio.create_task(self._permission_worker())
        if self._supervisor_task and not self._supervisor_task.done():
            if auto_connect:
                self._reconnect_event.set()
            return
        self._closing = False
        self._supervisor_task = asyncio.create_task(self._connection_supervisor())
        if auto_connect:
            self._reconnect_event.set()

    async def close(self) -> None:
        """关闭所有后台任务和网络资源，并唤醒等待中的 WebSocket 请求。"""
        self._closing = True
        self._reconnect_event.set()
        if self._supervisor_task:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
            self._supervisor_task = None
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._permission_worker_task:
            self._permission_worker_task.cancel()
            try:
                await self._permission_worker_task
            except asyncio.CancelledError:
                pass
            self._permission_worker_task = None
        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._ws = None
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._reconnect_after_disconnect = False
        self._reconnect_event.clear()
        self._mux.fail_waiters(CloudCLIError("CloudCLI connection closed."))

    async def ensure_connected(self) -> None:
        """确保 WebSocket 可用；并发调用时只允许一个协程真正执行连接过程。"""
        async with self._connect_lock:
            if self._ws and not self._ws.closed:
                return
            await self._connect_locked()

    async def get_active_sessions(self) -> dict[str, Any]:
        """通过 WebSocket 请求当前活跃 session 列表。"""
        await self.ensure_connected()
        response = await self._request(
            {"type": "get-active-sessions"},
            lambda item: item.get("type") == "active-sessions",
            request_key="active-sessions",
        )
        return response

    async def health_check(self) -> dict[str, Any]:
        """逐项检查认证、WebSocket、REST 和 Agent API 配置是否可用。"""
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
            result["auth"] = {"ok": False, "message": f"认证检查失败：{_redact_text(str(exc))}"}

        # WebSocket 检查会真实建立连接，因为 session/审批都依赖这条长连接。
        try:
            await self.ensure_connected()
            result["websocket"] = {"ok": True, "message": "WebSocket 已连接。"}
        except CloudCLIError as exc:
            result["websocket"] = {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            result["websocket"] = {
                "ok": False,
                "message": f"WebSocket 检查失败：{_redact_text(str(exc))}",
            }

        try:
            sessions = await self.get_recent_sessions(1)
            result["rest"] = {
                "ok": True,
                "message": f"REST 已可用，最近 session 返回 {len(sessions)} 条。",
            }
        except CloudCLIError as exc:
            result["rest"] = {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            result["rest"] = {"ok": False, "message": f"REST 检查失败：{_redact_text(str(exc))}"}

        # Agent API 可能启动真实任务，所以这里只检查 API key 配置，不主动调用 /api/agent。
        if self.config.api_key:
            result["agent"]["message"] = "已配置 cloudcli_api_key；为避免启动真实任务，未主动调用 /api/agent。"
        else:
            result["agent"]["message"] = "未配置 cloudcli_api_key；/cloudcli run 可能会被 CloudCLI 拒绝。"
        return result

    async def get_recent_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        """通过 REST 获取最近 session，供用户按序号绑定。"""
        return await self._rest.get_recent_sessions(limit)

    async def get_session_messages(
        self,
        session_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """通过 REST 读取某个 session 的历史消息。"""
        return await self._rest.get_session_messages(session_id, limit, offset)

    async def stream_agent(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """启动 CloudCLI agent 任务，并把 SSE 事件逐条返回给调用方。"""
        async for item in self._agent.stream_agent(payload):
            yield item

    async def _agent_auth_headers(self) -> dict[str, str]:
        """保留给测试或未来调用的 Agent API 鉴权头生成入口。"""
        return await self._auth.agent_headers()

    async def get_pending_permissions(self, session_id: str) -> list[PendingApproval]:
        """通过 WebSocket 查询指定 session 当前待审批权限。"""
        await self.ensure_connected()
        response = await self._request(
            {"type": "get-pending-permissions", "sessionId": session_id},
            lambda item: item.get("type") == "pending-permissions-response"
            and item.get("sessionId") == session_id,
            request_key=f"pending-permissions:{session_id}",
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
        session_id: str = "",
    ) -> None:
        """向 CloudCLI 发送审批结果；确认逻辑由 ApprovalService 负责。"""
        await self.ensure_connected()
        payload: dict[str, Any] = {
            "type": "claude-permission-response",
            "requestId": request_id,
            "allow": allow,
        }
        if session_id:
            payload["sessionId"] = session_id
        if message:
            payload["message"] = message
        await self._send_json(payload)

    async def abort_session(self, session_id: str, provider: str = "") -> AbortSessionResult:
        """发送中止 session 请求，并通过活跃 session 列表做短轮询确认。"""
        await self.ensure_connected()
        payload: dict[str, Any] = {
            "type": "abort-session",
            "sessionId": session_id,
        }
        if provider:
            payload["provider"] = provider
        await self._send_json(payload)
        return await self._confirm_abort_session(session_id, provider)

    async def _confirm_abort_session(
        self,
        session_id: str,
        provider: str = "",
    ) -> AbortSessionResult:
        """短时间轮询活跃列表，判断远端 session 是否已经不再运行。"""
        attempts = max(1, int(self.abort_confirm_attempts))
        delay = max(0.0, float(self.abort_confirm_delay_seconds))
        last_error = ""
        for attempt in range(attempts):
            if attempt > 0 and delay > 0:
                await asyncio.sleep(delay)
            try:
                active_payload = await self.get_active_sessions()
            except CloudCLIError as exc:
                last_error = str(exc)
                continue
            if not active_sessions_contains(active_payload, session_id, provider):
                return AbortSessionResult(
                    session_id=session_id,
                    provider=provider,
                    confirmed_inactive=True,
                )
        return AbortSessionResult(
            session_id=session_id,
            provider=provider,
            confirmed_inactive=False,
            confirmation_error=last_error,
        )

    async def _connect_locked(self) -> None:
        """在持有连接锁时建立 WebSocket；token 失效时尝试重新登录一次。"""
        if self._ws and not self._ws.closed:
            return
        await self._ensure_http_session()

        token = await self._get_token(allow_anonymous=self.config.allow_unauthenticated_ws)
        ws_url = self._ws_url(token)
        headers = self._auth_headers(token)
        try:
            ws = await self._session.ws_connect(
                ws_url,
                heartbeat=25,
                headers=headers,
            )
            self._ws = ws
        except Exception as exc:  # noqa: BLE001
            # 如果配置了用户名密码，第一次连接失败可能是缓存 token 过期，清掉后重登再试一次。
            if token and self.config.username and self.config.password:
                await self._clear_cached_token(force=True)
                try:
                    token = await self._get_token()
                    headers = self._auth_headers(token)
                    ws = await self._session.ws_connect(
                        self._ws_url(token),
                        heartbeat=25,
                        headers=headers,
                    )
                    self._ws = ws
                except Exception as retry_exc:  # noqa: BLE001
                    raise CloudCLIError(
                        f"无法连接 CloudCLI WebSocket，重新登录后仍失败：{_redact_text(str(retry_exc))}"
                    ) from retry_exc
                else:
                    self._start_reader(ws)
                    return
            raise CloudCLIError(f"无法连接 CloudCLI WebSocket：{_redact_text(str(exc))}") from exc

        self._start_reader(ws)

    def _start_reader(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """为当前 WebSocket 启动读取循环。"""
        task = asyncio.create_task(self._reader_loop(ws))
        self._reader_task = task
        task.add_done_callback(self._on_reader_done)

    def _on_reader_done(self, task: asyncio.Task) -> None:
        """读取循环结束时触发自动重连。"""
        if self._reader_task is task:
            self._reader_task = None
        if not self._closing:
            self._reconnect_after_disconnect = True
            self._reconnect_event.set()

    async def _connection_supervisor(self) -> None:
        """后台重连监督任务，使用指数退避避免 CloudCLI 不可用时频繁打日志。"""
        delay = max(0.01, float(self.reconnect_initial_seconds))
        max_delay = max(delay, float(self.reconnect_max_seconds))
        while not self._closing:
            try:
                await self._reconnect_event.wait()
                self._reconnect_event.clear()
                if self._closing:
                    return
                if self._ws and not self._ws.closed:
                    delay = max(0.01, float(self.reconnect_initial_seconds))
                    continue
                if self._reconnect_after_disconnect:
                    self._reconnect_after_disconnect = False
                    await asyncio.sleep(delay)
                await self.ensure_connected()
                delay = max(0.01, float(self.reconnect_initial_seconds))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "CloudCLI WebSocket reconnect failed: %s; retrying in %.1fs",
                    _redact_text(str(exc)),
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(max_delay, delay * 2)
                self._reconnect_event.set()

    async def _ensure_http_session(self) -> None:
        """懒创建共享 HTTP session；REST、登录和 WebSocket 握手都会复用它。"""
        if self._session and self._session.closed:
            self._session = None
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=max(3, self.config.timeout_seconds))
            self._session = create_http_session(timeout)

    async def _ensure_auth_http_session(self) -> aiohttp.ClientSession:
        """返回可用 HTTP session，供认证和 REST 子客户端使用。"""
        await self._ensure_http_session()
        if self._session is None:
            raise CloudCLIError("CloudCLI HTTP session 未初始化。")
        return self._session

    async def _get_token(self, *, allow_anonymous: bool = False) -> str:
        """读取或刷新 JWT token；匿名 WebSocket 模式可返回空 token。"""
        return await self._auth.get_token(allow_anonymous=allow_anonymous)

    async def _clear_cached_token(self, *, force: bool = False) -> None:
        """清理认证层缓存 token。"""
        await self._auth.clear_cached_token(force=force)

    def _auth_headers(self, token: str) -> dict[str, str]:
        """生成 WebSocket/REST 请求需要的鉴权头。"""
        return self._auth.headers(token)

    async def _request(
        self,
        payload: dict[str, Any],
        predicate: WaiterPredicate,
        *,
        request_key: str = "",
    ) -> dict[str, Any]:
        """发送一条 WebSocket 请求，并等待符合 predicate 的响应消息。"""
        await self.ensure_connected()
        try:
            return await self._mux.request(
                payload=payload,
                predicate=predicate,
                send_json=self._send_json,
                timeout_seconds=self.config.timeout_seconds,
                request_key=request_key,
            )
        except asyncio.TimeoutError as exc:
            raise CloudCLITimeout("等待 CloudCLI 响应超时。") from exc

    async def _send_json(self, payload: dict[str, Any]) -> None:
        """串行发送 WebSocket JSON，避免多个协程同时写同一连接。"""
        if not self._ws or self._ws.closed:
            raise CloudCLIError("CloudCLI WebSocket 未连接。")
        async with self._send_lock:
            await self._ws.send_json(payload)

    async def _reader_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """持续读取 WebSocket 消息，分发给请求等待者和权限请求处理器。"""
        disconnect_error: CloudCLIError | None = None
        try:
            async for message in ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    if len(message.data) > MAX_WS_MESSAGE_CHARS:
                        # WebSocket 没有 HTTP/SSE 那样的有限读取入口，必须在 JSON 解析前挡住异常大帧。
                        disconnect_error = CloudCLIError("CloudCLI WS 消息过大，已关闭连接。")
                        break
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
                    self._mux.fail_waiters(disconnect_error)

    async def _handle_message(self, data: Any) -> None:
        """处理单条 WebSocket 消息：先匹配请求响应，再识别异步权限请求。"""
        if not isinstance(data, dict):
            return

        await self._mux.handle_message(data)

        approval = self._extract_permission_request(data)
        if approval:
            # 权限回调可能触发状态写入和主动推送，放进队列能避免阻塞 WebSocket 读取循环。
            if self._permission_worker_task and not self._permission_worker_task.done():
                try:
                    self._permission_queue.put_nowait(approval)
                    return
                except asyncio.QueueFull:
                    logger.warning("CloudCLI permission queue is full; handling inline.")
            await self._deliver_permission_request(approval)

    async def _permission_worker(self) -> None:
        """串行处理权限请求，保证同一时间不会并发写入同一批审批状态。"""
        while True:
            approval = await self._permission_queue.get()
            try:
                await self._deliver_permission_request(approval)
            finally:
                self._permission_queue.task_done()

    async def _deliver_permission_request(self, approval: PendingApproval) -> None:
        """调用业务回调并吞掉异常，避免单条坏审批拖垮 WebSocket 客户端。"""
        try:
            await self._on_permission_request(approval)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to handle CloudCLI permission request: %s",
                _redact_text(str(exc)),
            )

    def _extract_permission_request(self, data: dict[str, Any]) -> PendingApproval | None:
        """兼容不同 CloudCLI 事件命名，提取标准 PendingApproval 对象。"""
        message_type = str(data.get("type") or data.get("kind") or "")
        if message_type not in {"permission_request", "permission-request"}:
            has_shape = data.get("requestId") and data.get("toolName") and data.get("sessionId")
            if not has_shape:
                return None
        return PendingApproval.from_cloudcli(data)

    def _api_url(self, path: str) -> str:
        """拼接 REST API URL。"""
        return build_api_url(self.config.base_url, path)

    def _ws_url(self, token: str) -> str:
        """拼接 WebSocket URL；token 参数保留给历史兼容。"""
        return build_ws_url(self.config.base_url, token)


def _redact_text(value: str) -> str:
    """统一在网络错误中隐藏 token、密码和 API key。"""
    return redact_error_text(value)
