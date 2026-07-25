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
- ``SHADOWSHIELD_POLICY_STATE_PATH`` - durable anti-replay state file.

Keys are compared with :func:`hmac.compare_digest` (constant-time) at request time.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from typing import Any

MAX_HTTP_BODY_BYTES = 1_048_576
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


def resolve_policy_state_path(explicit: str | None = None) -> str | None:
    """Durable anti-replay state path from args or the deployment environment."""
    return explicit or os.environ.get("SHADOWSHIELD_POLICY_STATE_PATH") or None


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
    """Buffer and reject oversized HTTP bodies before framework JSON parsing.

    These endpoints accept bounded JSON rather than streaming uploads. Buffering
    at most ``max_bytes`` gives deterministic 413 behavior even for chunked
    requests without a ``Content-Length`` header.
    """

    def __init__(self, app: Any, max_bytes: int = MAX_HTTP_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

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

        buffered: list[dict[str, Any]] = []
        received = 0
        while True:
            message = dict(await receive())
            buffered.append(message)
            if message.get("type") != "http.request":
                break
            received += len(message.get("body", b""))
            if received > self.max_bytes:
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break

        index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

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
        except TimeoutError:
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
    """Authenticate protected routes before reading or parsing their bodies."""

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
        method = str(scope.get("method", "GET")).upper()
        if (
            scope.get("type") == "http"
            and method != "OPTIONS"
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
        if scope.get("type") == "http" and method != "OPTIONS" and protected and self.api_keys:
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
