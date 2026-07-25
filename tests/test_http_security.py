"""Framework-independent regression tests for the ASGI security boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from shadowshield._security import (
    MAX_HTTP_BODY_BYTES,
    ConcurrencyLimitMiddleware,
    RequestBodyLimitMiddleware,
)


def test_chunked_body_limit_rejects_before_inner_response() -> None:
    chunks = iter(
        [
            {"type": "http.request", "body": b"x" * 600_000, "more_body": True},
            {"type": "http.request", "body": b"x" * 600_000, "more_body": False},
        ]
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return next(chunks)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def inner(
        scope: dict[str, Any],
        receive_inner: Callable[[], Awaitable[dict[str, Any]]],
        send_inner: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        while True:
            message = await receive_inner()
            if not message.get("more_body"):
                break
        await send_inner({"type": "http.response.start", "status": 200, "headers": []})
        await send_inner({"type": "http.response.body", "body": b"ok"})

    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    asyncio.run(RequestBodyLimitMiddleware(inner)(scope, receive, send))

    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert starts == [
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"35"),
            ],
        }
    ]


def test_chunked_body_limit_rejects_before_framework_is_called() -> None:
    chunks = iter(
        [
            {
                "type": "http.request",
                "body": b"x" * (MAX_HTTP_BODY_BYTES // 2 + 1),
                "more_body": True,
            },
            {
                "type": "http.request",
                "body": b"x" * (MAX_HTTP_BODY_BYTES // 2 + 1),
                "more_body": False,
            },
        ]
    )
    sent: list[dict[str, Any]] = []
    inner_called = False

    async def receive() -> dict[str, Any]:
        return next(chunks)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def framework(
        scope: dict[str, Any],
        receive_inner: Callable[[], Awaitable[dict[str, Any]]],
        send_inner: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        nonlocal inner_called
        inner_called = True

    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    asyncio.run(RequestBodyLimitMiddleware(framework)(scope, receive, send))

    assert inner_called is False
    assert sent[0]["status"] == 413


def test_scan_capacity_rejects_without_blocking_health() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        responses: list[dict[str, Any]] = []

        async def inner(scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["path"] == "/health":
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"ok"})
                return
            entered.set()
            await release.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            responses.append(message)

        middleware = ConcurrencyLimitMiddleware(
            inner,
            protected_paths=("/scan",),
            max_concurrency=1,
        )
        first = asyncio.create_task(middleware({"type": "http", "path": "/scan"}, receive, send))
        await entered.wait()
        await middleware({"type": "http", "path": "/scan"}, receive, send)
        await middleware({"type": "http", "path": "/health"}, receive, send)
        release.set()
        await first

        statuses = [
            message["status"] for message in responses if message["type"] == "http.response.start"
        ]
        assert 503 in statuses
        assert 200 in statuses

    asyncio.run(scenario())
