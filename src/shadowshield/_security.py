"""Shared HTTP-security helpers for the optional servers.

Both :mod:`shadowshield.server` (minimal API) and :mod:`shadowshield.control`
(full dashboard) are security-sensitive control planes. These helpers provide
early API-key/bearer auth, request-size enforcement, browser response hardening,
and CORS without each server reinventing them.

Nothing here imports FastAPI - the FastAPI-dependent bits (the auth dependency,
the CORS middleware) are built inside each app factory where FastAPI is already
imported lazily. This module stays import-safe even without the ``dashboard`` extra.

Configuration precedence: explicit arguments first, then environment:

- ``SHADOWSHIELD_API_KEY``     - comma-separated list of accepted keys.
- ``SHADOWSHIELD_ADMIN_KEY``   - comma-separated control/metrics administrator keys.
- ``SHADOWSHIELD_CORS_ORIGINS`` - comma-separated list of allowed origins.
- ``SHADOWSHIELD_POLICY_KEY``  - HMAC key required for remotely exposed policy updates.
- ``SHADOWSHIELD_POLICY_STATE_KEY`` - independent HMAC key for durable policy state.
- ``SHADOWSHIELD_POLICY_STATE_PATH`` - durable anti-replay state file.

Keys are compared with :func:`hmac.compare_digest` (constant-time) at request time.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from collections.abc import Sequence
from math import isfinite
from time import monotonic
from typing import Any

MAX_HTTP_BODY_BYTES = 1_048_576
MAX_HTTP_BODY_FRAMES = 8_192
HTTP_BODY_READ_TIMEOUT_SECONDS = 15.0
MAX_CONCURRENT_SCANS = 16


def _split_csv(value: str | None) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()] if value else []


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out


def resolve_api_keys(explicit: list[str] | None = None) -> list[str]:
    """Accepted API keys: explicit args + ``SHADOWSHIELD_API_KEY`` (de-duplicated)."""
    keys = list(explicit or [])
    keys += _split_csv(os.environ.get("SHADOWSHIELD_API_KEY"))
    return _dedupe(keys)


def resolve_admin_keys(explicit: list[str] | None = None) -> list[str]:
    """Administrator keys from explicit args + ``SHADOWSHIELD_ADMIN_KEY``."""
    keys = list(explicit or [])
    keys += _split_csv(os.environ.get("SHADOWSHIELD_ADMIN_KEY"))
    return _dedupe(keys)


def resolve_cors_origins(explicit: list[str] | None = None) -> list[str]:
    """Allowed CORS origins: explicit args + ``SHADOWSHIELD_CORS_ORIGINS``."""
    origins = list(explicit or [])
    origins += _split_csv(os.environ.get("SHADOWSHIELD_CORS_ORIGINS"))
    return _dedupe(origins)


def resolve_policy_key(explicit: bytes | str | None = None) -> bytes | None:
    """Policy HMAC key from an explicit value or ``SHADOWSHIELD_POLICY_KEY``."""
    value: bytes | str | None = explicit or os.environ.get("SHADOWSHIELD_POLICY_KEY")
    if isinstance(value, str):
        return value.encode("utf-8") if value else None
    return value


def resolve_policy_state_key(explicit: bytes | str | None = None) -> bytes | None:
    """Policy-state HMAC key from args or ``SHADOWSHIELD_POLICY_STATE_KEY``."""
    value: bytes | str | None = explicit or os.environ.get("SHADOWSHIELD_POLICY_STATE_KEY")
    if isinstance(value, str):
        return value.encode("utf-8") if value else None
    return value


def resolve_policy_state_path(explicit: str | None = None) -> str | None:
    """Durable anti-replay state path from args or the deployment environment."""
    return explicit or os.environ.get("SHADOWSHIELD_POLICY_STATE_PATH") or None


def secret_groups_overlap(
    left: Sequence[bytes | str],
    right: Sequence[bytes | str],
) -> bool:
    """Return whether two credential groups share a value.

    Every candidate comparison uses :func:`hmac.compare_digest`; the loops do
    not short-circuit when a match is found.
    """

    overlap = False
    for left_value in left:
        left_bytes = left_value.encode("utf-8") if isinstance(left_value, str) else left_value
        for right_value in right:
            right_bytes = (
                right_value.encode("utf-8") if isinstance(right_value, str) else right_value
            )
            overlap |= hmac.compare_digest(left_bytes, right_bytes)
    return overlap


def extract_key(x_api_key: str | None, authorization: str | None) -> str | None:
    """Pull a presented key from either the ``X-API-Key`` or ``Bearer`` header."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def key_is_valid(supplied: str | None, keys: list[str]) -> bool:
    """Constant-time check that ``supplied`` matches one of ``keys``.

    Compares UTF-8 bytes so a non-ASCII supplied key yields a clean ``False`` rather than
    a ``TypeError`` from :func:`hmac.compare_digest` (which rejects non-ASCII ``str``).
    """
    if not supplied:
        return False
    supplied_b = supplied.encode("utf-8")
    return any(hmac.compare_digest(supplied_b, k.encode("utf-8")) for k in keys)


def is_loopback(host: str) -> bool:
    """True for hosts that are not reachable off-box (no auth warning needed)."""
    return host in {"127.0.0.1", "localhost", "::1", ""}


class RequestBodyLimitMiddleware:
    """Coalesce and reject unsafe HTTP bodies before framework JSON parsing.

    These endpoints accept bounded JSON rather than streaming uploads. The
    aggregate buffer never exceeds ``max_bytes``, so many tiny ASGI frames cannot
    amplify a legal body into unbounded Python object overhead. A frame ceiling
    bounds receive-loop work, and one total deadline covers the complete body
    rather than resetting for every chunk.
    """

    def __init__(
        self,
        app: Any,
        max_bytes: int = MAX_HTTP_BODY_BYTES,
        *,
        max_frames: int = MAX_HTTP_BODY_FRAMES,
        read_timeout_seconds: float = HTTP_BODY_READ_TIMEOUT_SECONDS,
    ) -> None:
        if isinstance(max_frames, bool) or not isinstance(max_frames, int) or max_frames <= 0:
            raise ValueError("max_frames must be a positive integer")
        if isinstance(read_timeout_seconds, bool) or not isinstance(
            read_timeout_seconds, (int, float)
        ):
            raise ValueError("read_timeout_seconds must be a finite positive number")
        try:
            normalized_timeout = float(read_timeout_seconds)
        except OverflowError:
            raise ValueError("read_timeout_seconds must be a finite positive number") from None
        if not isfinite(normalized_timeout) or normalized_timeout <= 0:
            raise ValueError("read_timeout_seconds must be a finite positive number")
        self.app = app
        self.max_bytes = max_bytes
        self.max_frames = max_frames
        self.read_timeout_seconds = normalized_timeout

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        body = bytearray()
        frame_count = 0
        body_complete = False
        terminal_message: dict[str, Any] | None = None
        deadline = monotonic() + self.read_timeout_seconds
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                await self._reject_timeout(send)
                return
            try:
                message = dict(await asyncio.wait_for(receive(), timeout=remaining))
            except asyncio.TimeoutError:
                await self._reject_timeout(send)
                return
            if message.get("type") != "http.request":
                terminal_message = message
                break

            frame_count += 1
            if frame_count > self.max_frames:
                await self._reject_fragmented(send)
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                await self._reject(send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                body_complete = True
                break

        aggregate_pending = bool(body) or body_complete
        aggregate = bytes(body)

        async def replay_receive() -> dict[str, Any]:
            nonlocal aggregate_pending, terminal_message
            if aggregate_pending:
                aggregate_pending = False
                return {
                    "type": "http.request",
                    "body": aggregate,
                    "more_body": not body_complete,
                }
            if terminal_message is not None:
                message = terminal_message
                terminal_message = None
                return message
            # The body has been fully delivered. Delegate to the real channel so
            # disconnect listeners (e.g. Starlette's StreamingResponse) observe
            # http.disconnect instead of spinning on fabricated empty bodies.
            message = await receive()
            return dict(message) if isinstance(message, dict) else {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _reject_fragmented(send: Any) -> None:
        body = b'{"detail":"request body too fragmented"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _reject_timeout(send: Any) -> None:
        body = b'{"detail":"request body read timed out"}'
        await send(
            {
                "type": "http.response.start",
                "status": 408,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class ConcurrencyLimitMiddleware:
    """Bound expensive scan/benchmark work while leaving health responsive."""

    def __init__(
        self,
        app: Any,
        *,
        protected_paths: tuple[str, ...],
        protected_prefixes: tuple[str, ...] = (),
        max_concurrency: int = MAX_CONCURRENT_SCANS,
    ) -> None:
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero")
        self.app = app
        self.protected_paths = frozenset(protected_paths)
        self.protected_prefixes = protected_prefixes
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = str(scope.get("path", ""))
        protected = path in self.protected_paths or any(
            path.startswith(prefix) for prefix in self.protected_prefixes
        )
        if scope.get("type") != "http" or not protected:
            await self.app(scope, receive, send)
            return
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=0.01)
        except asyncio.TimeoutError:
            body = b'{"detail":"server is at scan capacity"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"retry-after", b"1"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self._semaphore.release()


class EarlyAuthMiddleware:
    """Authenticate protected routes before reading or parsing their bodies.

    Configured CORS middleware sits outside this boundary and handles valid
    browser preflights. Arbitrary ``OPTIONS`` requests that reach this layer are
    authenticated like every other protected request, so they cannot consume
    body-read or scan-admission capacity anonymously.
    """

    def __init__(
        self,
        app: Any,
        *,
        api_keys: list[str],
        protected_paths: tuple[str, ...],
        protected_prefixes: tuple[str, ...] = (),
        deny_when_unconfigured: bool = False,
    ) -> None:
        self.app = app
        self.api_keys = api_keys
        self.protected_paths = frozenset(protected_paths)
        self.protected_prefixes = protected_prefixes
        self.deny_when_unconfigured = deny_when_unconfigured

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = str(scope.get("path", ""))
        protected = path in self.protected_paths or any(
            path.startswith(prefix) for prefix in self.protected_prefixes
        )
        if (
            scope.get("type") == "http"
            and protected
            and self.deny_when_unconfigured
            and not self.api_keys
        ):
            body = json.dumps({"detail": "administrative API is disabled"}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        if scope.get("type") == "http" and protected and self.api_keys:
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers", [])
            }
            supplied = extract_key(headers.get("x-api-key"), headers.get("authorization"))
            if not key_is_valid(supplied, self.api_keys):
                body = json.dumps({"detail": "missing or invalid API key"}).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                            (b"www-authenticate", b"Bearer"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Attach conservative browser and cache headers to every HTTP response."""

    _BASE_HEADERS = (
        (
            b"content-security-policy",
            b"default-src 'self'; style-src 'self' 'unsafe-inline'; "
            b"script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            b"connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
        (b"cache-control", b"no-store"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"referrer-policy", b"no-referrer"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
    )

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_headers = {k.lower(): v for k, v in scope.get("headers", [])}
        is_https = (
            scope.get("scheme") == "https" or request_headers.get(b"x-forwarded-proto") == b"https"
        )

        async def send_hardened(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                additions = list(self._BASE_HEADERS)
                if is_https:
                    additions.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                replaced = {name for name, _ in additions}
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in replaced
                ]
                message = {**message, "headers": [*headers, *additions]}
            await send(message)

        await self.app(scope, receive, send_hardened)
