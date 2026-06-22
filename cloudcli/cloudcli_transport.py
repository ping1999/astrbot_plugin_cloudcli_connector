from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


WaiterPredicate = Callable[[dict[str, Any]], bool]
SendJson = Callable[[dict[str, Any]], Awaitable[None]]


class WebSocketRequestMux:
    """Match WebSocket responses to requests and serialize ambiguous request groups."""

    def __init__(self) -> None:
        self._waiters: list[tuple[WaiterPredicate, asyncio.Future]] = []
        self._request_locks: dict[str, asyncio.Lock] = {}

    async def request(
        self,
        *,
        payload: dict[str, Any],
        predicate: WaiterPredicate,
        send_json: SendJson,
        timeout_seconds: int,
        request_key: str = "",
    ) -> dict[str, Any]:
        if request_key:
            lock = self._request_locks.setdefault(request_key, asyncio.Lock())
            async with lock:
                return await self._request_once(
                    payload=payload,
                    predicate=predicate,
                    send_json=send_json,
                    timeout_seconds=timeout_seconds,
                )
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
        for _, future in self._waiters:
            if not future.done():
                future.set_exception(exc)
        self._waiters = []
