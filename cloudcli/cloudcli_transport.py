"""WebSocket 请求复用器：把异步消息流中的响应匹配回发起请求的协程。"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


WaiterPredicate = Callable[[dict[str, Any]], bool]
SendJson = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class _RequestLockSlot:
    """同一 request_key 的串行化锁，ref_count 用来在最后一个请求结束后回收锁。"""

    lock: asyncio.Lock
    ref_count: int = 0


class WebSocketRequestMux:
    """匹配 WebSocket 响应，并串行化无法区分的同类请求。"""

    def __init__(self) -> None:
        self._waiters: list[tuple[WaiterPredicate, asyncio.Future]] = []
        self._request_locks: dict[str, _RequestLockSlot] = {}

    async def request(
        self,
        *,
        payload: dict[str, Any],
        predicate: WaiterPredicate,
        send_json: SendJson,
        timeout_seconds: int,
        request_key: str = "",
    ) -> dict[str, Any]:
        """发送请求并等待响应；request_key 相同的请求会排队执行。"""
        if request_key:
            slot = self._request_locks.get(request_key)
            if slot is None:
                slot = _RequestLockSlot(asyncio.Lock())
                self._request_locks[request_key] = slot
            slot.ref_count += 1
            try:
                async with slot.lock:
                    return await self._request_once(
                        payload=payload,
                        predicate=predicate,
                        send_json=send_json,
                        timeout_seconds=timeout_seconds,
                    )
            finally:
                slot.ref_count -= 1
                if slot.ref_count <= 0 and not slot.lock.locked():
                    if self._request_locks.get(request_key) is slot:
                        self._request_locks.pop(request_key, None)
        return await self._request_once(
            payload=payload,
            predicate=predicate,
            send_json=send_json,
            timeout_seconds=timeout_seconds,
        )

    async def _request_once(
        self,
        *,
        payload: dict[str, Any],
        predicate: WaiterPredicate,
        send_json: SendJson,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        """注册等待者、发送 payload，然后等待第一条匹配 predicate 的消息。"""
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._waiters.append((predicate, future))
        try:
            await send_json(payload)
            return await asyncio.wait_for(future, timeout=max(2, timeout_seconds))
        finally:
            self._waiters = [
                (match, waiter)
                for match, waiter in self._waiters
                if waiter is not future
            ]

    async def handle_message(self, data: dict[str, Any]) -> None:
        """把收到的消息交给所有等待者，predicate 命中的 future 会被唤醒。"""
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

    def fail_waiters(self, exc: Exception) -> None:
        """连接断开或关闭时，让所有等待中的请求立即失败。"""
        for _, future in self._waiters:
            if not future.done():
                future.set_exception(exc)
        self._waiters = []
