"""Framework-independent regression tests for the ASGI security boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from shadowshield._security import (
    MAX_HTTP_BODY_BYTES,
    ConcurrencyLimitMiddleware,
    EarlyAuthMiddleware,
    RequestBodyLimitMiddleware,
    resolve_api_keys,
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


def test_many_tiny_body_frames_are_replayed_as_one_bounded_aggregate() -> None:
    payload = bytes(index % 251 for index in range(4_096))
    offset = 0
    downstream_messages: list[dict[str, Any]] = []
    downstream_body = bytearray()

    async def receive() -> dict[str, Any]:
        nonlocal offset
        chunk = payload[offset : offset + 1]
        offset += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": offset < len(payload),
        }

    async def send(message: dict[str, Any]) -> None:
        return None

    async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
        while True:
            message = await receive_inner()
            downstream_messages.append(message)
            downstream_body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break

    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    asyncio.run(RequestBodyLimitMiddleware(framework)(scope, receive, send))

    assert bytes(downstream_body) == payload
    assert downstream_messages == [
        {
            "type": "http.request",
            "body": payload,
            "more_body": False,
        }
    ]


def test_body_frame_ceiling_rejects_pathological_fragmentation() -> None:
    sent: list[dict[str, Any]] = []
    framework_called = False

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
        nonlocal framework_called
        framework_called = True

    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    middleware = RequestBodyLimitMiddleware(framework, max_frames=4)
    asyncio.run(middleware(scope, receive, send))

    assert framework_called is False
    assert sent[0]["status"] == 413
    assert sent[1]["body"] == b'{"detail":"request body too fragmented"}'


def test_stalled_body_receive_returns_controlled_timeout() -> None:
    sent: list[dict[str, Any]] = []
    framework_called = False

    async def scenario() -> None:
        stalled = asyncio.Event()

        async def receive() -> dict[str, Any]:
            await stalled.wait()
            raise AssertionError("stalled receive unexpectedly resumed")

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
            nonlocal framework_called
            framework_called = True

        scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
        middleware = RequestBodyLimitMiddleware(framework, read_timeout_seconds=0.01)
        await middleware(scope, receive, send)

    asyncio.run(scenario())

    assert framework_called is False
    assert sent[0]["status"] == 408
    assert sent[1]["body"] == b'{"detail":"request body read timed out"}'


def test_body_read_deadline_does_not_reset_for_each_frame(monkeypatch: Any) -> None:
    now = 0.0
    sent: list[dict[str, Any]] = []
    framework_called = False

    def clock() -> float:
        return now

    monkeypatch.setattr("shadowshield._security.monotonic", clock)

    async def receive() -> dict[str, Any]:
        nonlocal now
        now += 0.4
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
        nonlocal framework_called
        framework_called = True

    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    middleware = RequestBodyLimitMiddleware(framework, read_timeout_seconds=1.0)
    asyncio.run(middleware(scope, receive, send))

    assert framework_called is False
    assert sent[0]["status"] == 408


def test_early_auth_rejects_without_reading_or_buffering_body() -> None:
    sent: list[dict[str, Any]] = []
    receive_called = False
    framework_called = False

    async def receive() -> dict[str, Any]:
        nonlocal receive_called
        receive_called = True
        return {
            "type": "http.request",
            "body": b"x" * MAX_HTTP_BODY_BYTES,
            "more_body": True,
        }

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
        nonlocal framework_called
        framework_called = True

    body_limited = RequestBodyLimitMiddleware(framework, read_timeout_seconds=0.01)
    authenticated = EarlyAuthMiddleware(
        body_limited,
        api_keys=["valid-key"],
        protected_paths=("/scan",),
    )
    scope = {"type": "http", "method": "POST", "path": "/scan", "headers": []}
    asyncio.run(authenticated(scope, receive, send))

    assert receive_called is False
    assert framework_called is False
    assert sent[0]["status"] == 401


def test_early_auth_does_not_exempt_arbitrary_options_bodies() -> None:
    sent: list[dict[str, Any]] = []
    receive_called = False
    framework_called = False

    async def receive() -> dict[str, Any]:
        nonlocal receive_called
        receive_called = True
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def framework(scope: dict[str, Any], receive_inner: Any, send_inner: Any) -> None:
        nonlocal framework_called
        framework_called = True

    authenticated = EarlyAuthMiddleware(
        framework,
        api_keys=["valid-key"],
        protected_paths=("/scan",),
    )
    scope = {"type": "http", "method": "OPTIONS", "path": "/scan", "headers": []}
    asyncio.run(authenticated(scope, receive, send))

    assert receive_called is False
    assert framework_called is False
    assert sent[0]["status"] == 401


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


def test_resolve_api_keys_isolated_ignores_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHADOWSHIELD_API_KEY", "ambient-key")
    assert resolve_api_keys(["explicit-key"], include_environment=False) == ["explicit-key"]


def test_resolve_api_keys_isolated_returns_only_explicit_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHADOWSHIELD_API_KEY", "ambient-1, ambient-2")
    resolved = resolve_api_keys(["explicit-1", "explicit-2"], include_environment=False)
    assert resolved == ["explicit-1", "explicit-2"]
    assert "ambient-1" not in resolved
    assert "ambient-2" not in resolved


def test_resolve_api_keys_isolated_requires_nonempty_key_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Isolated auth must fail closed: a missing secret never disables auth."""
    monkeypatch.setenv("SHADOWSHIELD_API_KEY", "ambient-key")
    with pytest.raises(ValueError, match="isolated authentication requires an explicit API key"):
        resolve_api_keys(None, include_environment=False)
    with pytest.raises(ValueError, match="isolated authentication requires an explicit API key"):
        resolve_api_keys([], include_environment=False)


def test_resolve_api_keys_default_merges_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """include_environment=True (the default) keeps the ambient key merged."""
    monkeypatch.setenv("SHADOWSHIELD_API_KEY", "ambient-key, explicit-key")
    assert resolve_api_keys(["explicit-key"]) == ["explicit-key", "ambient-key"]
    assert resolve_api_keys(None) == ["ambient-key", "explicit-key"]
