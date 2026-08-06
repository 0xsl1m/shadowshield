"""OpenAI-compatible reverse proxy ("gateway mode").

``shadowshield proxy --upstream https://api.openai.com`` puts the shield *in
front of* any OpenAI-compatible chat endpoint, so applications get input and
output guardrails with a one-line base-URL change — no SDK integration at all:

- **Request side**: every chat message is scanned (INPUT direction) before the
  request is forwarded. A terminal decision (BLOCK/ESCALATE) short-circuits
  with an OpenAI-style ``403`` error; the upstream is never called.
- **Response side, non-streaming**: completion text is scanned (OUTPUT
  direction); a terminal decision replaces the body with the same ``403``
  error shape — offending content is never returned to the caller.
- **Response side, streaming (SSE)**: chunks pass through in real time while a
  :class:`~shadowshield.core.stream.StreamScanner` evaluates the growing
  completion. On a terminal decision the stream is cut mid-flight and
  terminated with an OpenAI-conventional ``finish_reason="content_filter"``
  chunk followed by ``data: [DONE]``.

Auth, body limits, concurrency caps, and security headers reuse the shared
:mod:`shadowshield._security` middleware. When proxy auth keys are configured
(``--api-key`` / ``SHADOWSHIELD_API_KEY``) clients authenticate with
``X-API-Key`` or ``Bearer``; ``X-API-Key`` is *never* forwarded upstream, so
upstream credentials must travel in the ``Authorization`` header.

Requires the ``dashboard`` extra: ``pip install shadowshield[dashboard]``.

Note: this module deliberately does *not* use ``from __future__ import
annotations``. FastAPI is imported lazily inside :func:`create_proxy_app`, and
endpoint annotations (``request: Request``) must evaluate to real classes at
definition time — lazy string annotations would resolve against the module
namespace where FastAPI names do not exist, breaking request injection.
"""

import asyncio
import hashlib
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import structlog

from ._security import (
    ConcurrencyLimitMiddleware,
    EarlyAuthMiddleware,
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    extract_key,
    is_loopback,
    resolve_api_keys,
)
from .core.shield import Shield
from .core.types import Decision, Direction, ScanResult

logger = structlog.get_logger("shadowshield.proxy")

# Hop-by-hop headers never forwarded in either direction (RFC 9110 §7.6.1),
# plus framing headers that no longer describe a (possibly modified) body.
_REQUEST_HEADER_DENYLIST = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        # Proxy credential — never leaked upstream (see module docstring).
        "x-api-key",
    }
)
_RESPONSE_HEADER_DENYLIST = frozenset(
    {
        "content-length",
        "content-encoding",
        "connection",
        "keep-alive",
        "transfer-encoding",
    }
)

#: At most this many chat messages / completion choices are scanned per call.
_MAX_MESSAGES_SCANNED = 128
_MAX_CHOICES_SCANNED = 16

_TERMINAL = frozenset({Decision.BLOCK, Decision.ESCALATE})


def _is_terminal(result: ScanResult) -> bool:
    return result.decision in _TERMINAL


def _message_texts(payload: dict[str, Any]) -> list[str]:
    """Extract scannable text from an OpenAI chat/completions request."""
    texts: list[str] = []
    messages = payload.get("messages")
    if isinstance(messages, list):
        for message in messages[:_MAX_MESSAGES_SCANNED]:
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                parts = [
                    part["text"]
                    for part in content
                    if isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("text"), str)
                ]
                if parts:
                    texts.append("\n".join(parts))
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        texts.append(prompt)
    return texts


def _response_texts(body: dict[str, Any]) -> list[str]:
    """Extract scannable text from a non-streaming completion response."""
    texts: list[str] = []
    choices = body.get("choices")
    if isinstance(choices, list):
        for choice in choices[:_MAX_CHOICES_SCANNED]:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                texts.append(message["content"])
            if isinstance(choice.get("text"), str):
                texts.append(choice["text"])
    return texts


def _stream_delta_text(chunk: dict[str, Any]) -> str:
    """Extract newly emitted text from one SSE completion chunk."""
    parts: list[str] = []
    choices = chunk.get("choices")
    if isinstance(choices, list):
        for choice in choices[:_MAX_CHOICES_SCANNED]:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                parts.append(delta["content"])
            if isinstance(choice.get("text"), str):
                parts.append(choice["text"])
    return "".join(parts)


def _try_json(data: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _content_filter_tail(template: dict[str, Any] | None) -> bytes:
    """OpenAI-conventional stream termination for a policy-blocked completion."""
    template = template or {}
    chunk = {
        "id": template.get("id", "chatcmpl-shadowshield"),
        "object": template.get("object", "chat.completion.chunk"),
        "created": int(template.get("created", time.time())),
        "model": template.get("model", ""),
        "choices": [{"index": 0, "delta": {}, "finish_reason": "content_filter"}],
    }
    return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode()


def _blocked_error(result: ScanResult, phase: str) -> dict[str, Any]:
    """OpenAI-style error body. Never includes payload content or excerpts."""
    return {
        "error": {
            "message": f"{phase} blocked by ShadowShield policy (decision={result.decision.value})",
            "type": "content_policy_violation",
            "param": None,
            "code": "shadowshield_blocked",
        }
    }


def _forward_headers(request_headers: Any) -> dict[str, str]:
    return {
        name: value
        for name, value in request_headers.items()
        if name.lower() not in _REQUEST_HEADER_DENYLIST
    }


def _response_headers(upstream_headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in upstream_headers.items()
        if name.lower() not in _RESPONSE_HEADER_DENYLIST
    }


def _identity_for(request: Any) -> str | None:
    """Stable, non-reversible caller identity for rate limiting."""
    supplied = extract_key(request.headers.get("x-api-key"), request.headers.get("authorization"))
    if supplied:
        return "key:" + hashlib.sha256(supplied.encode("utf-8")).hexdigest()[:16]
    client = getattr(request, "client", None)
    return f"ip:{client.host}" if client is not None else None


def create_proxy_app(
    shield: Shield,
    upstream: str,
    *,
    api_keys: list[str] | None = None,
    scan_request: bool = True,
    scan_response: bool = True,
    timeout_seconds: float = 120.0,
    stream_scan_interval_chars: int = 256,
    stream_carry_chars: int = 2_048,
    transport: Any | None = None,
) -> Any:
    """Build the proxy ASGI app guarding an OpenAI-compatible ``upstream``.

    Args:
        shield: the shield whose engine/policy scans both directions.
        upstream: base URL of the upstream API (``http(s)://host[:port][/prefix]``).
        api_keys: proxy access keys (X-API-Key/Bearer); also read from
            ``SHADOWSHIELD_API_KEY``. Empty = unauthenticated (loopback only).
        scan_request: scan chat messages before forwarding (default on).
        scan_response: scan completion text before returning (default on).
        timeout_seconds: upstream request timeout.
        stream_scan_interval_chars / stream_carry_chars: StreamScanner tuning
            for SSE completions — lower intervals cut malicious streams sooner.
        transport: optional httpx transport (tests / custom routing).
    """
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse, Response, StreamingResponse
    except ImportError as exc:  # pragma: no cover - exercised without extra
        raise ImportError(
            "The proxy requires the 'dashboard' extra: pip install shadowshield[dashboard]"
        ) from exc

    if not upstream.startswith(("http://", "https://")):
        raise ValueError(f"upstream must be an http(s) URL, got {upstream!r}")
    upstream = upstream.rstrip("/")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    keys = resolve_api_keys(api_keys)
    client = httpx.AsyncClient(timeout=timeout_seconds, transport=transport)

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        async with client:
            yield

    app = FastAPI(title="ShadowShield Proxy", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.add_middleware(RequestBodyLimitMiddleware)
    app.add_middleware(ConcurrencyLimitMiddleware, protected_paths=(), protected_prefixes=("/v1",))
    app.add_middleware(
        EarlyAuthMiddleware, api_keys=keys, protected_paths=(), protected_prefixes=("/v1",)
    )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def _scan_request_messages(payload: dict[str, Any], identity: str | None) -> Any | None:
        """Return a 403 response if any message terminates, else None."""
        if not scan_request:
            return None
        for text in _message_texts(payload):
            result = await asyncio.to_thread(
                shield.scan, text, direction=Direction.INPUT, identity=identity
            )
            if _is_terminal(result):
                logger.warning(
                    "shadowshield.proxy.request_blocked",
                    decision=result.decision.value,
                    severity=result.severity.name,
                    score=round(result.score, 4),
                )
                return JSONResponse(status_code=403, content=_blocked_error(result, "request"))
        return None

    async def _forward_non_stream(
        request: Request, target: str, body: bytes, identity: str | None
    ) -> Any:
        upstream_response = await client.request(
            request.method, target, content=body, headers=_forward_headers(request.headers)
        )
        content_type = upstream_response.headers.get("content-type", "")
        if scan_response and upstream_response.status_code < 400 and "json" in content_type:
            parsed = _try_json(upstream_response.text)
            if parsed is not None:
                for text in _response_texts(parsed):
                    result = await asyncio.to_thread(
                        shield.scan, text, direction=Direction.OUTPUT, identity=identity
                    )
                    if _is_terminal(result):
                        logger.warning(
                            "shadowshield.proxy.response_blocked",
                            decision=result.decision.value,
                            severity=result.severity.name,
                            score=round(result.score, 4),
                        )
                        return JSONResponse(
                            status_code=403, content=_blocked_error(result, "response")
                        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=_response_headers(upstream_response.headers),
        )

    async def _forward_stream(
        request: Request, target: str, body: bytes, identity: str | None
    ) -> Any:
        # Open the upstream stream eagerly so its status line is known before
        # we commit to our own response status.
        stream_cm = client.stream(
            request.method, target, content=body, headers=_forward_headers(request.headers)
        )
        upstream_response = await stream_cm.__aenter__()
        media_type = upstream_response.headers.get("content-type", "text/event-stream")
        scanner = shield.stream_scanner(
            direction=Direction.OUTPUT,
            identity=identity,
            scan_interval_chars=stream_scan_interval_chars,
            carry_chars=stream_carry_chars,
        )

        async def events() -> AsyncIterator[bytes]:
            first_chunk: dict[str, Any] | None = None
            blocked_result: ScanResult | None = None
            try:
                if upstream_response.status_code >= 400 or "text/event-stream" not in media_type:
                    # Not a successful SSE stream: forward verbatim, no scanning.
                    async for raw in upstream_response.aiter_bytes():
                        yield raw
                    return
                async for line in upstream_response.aiter_lines():
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        if data and data != "[DONE]":
                            parsed = _try_json(data)
                            if parsed is not None:
                                if first_chunk is None:
                                    first_chunk = parsed
                                delta = _stream_delta_text(parsed)
                                if delta and scan_response:
                                    terminal = await asyncio.to_thread(scanner.feed, delta)
                                    if terminal is not None:
                                        blocked_result = terminal
                                        break
                    # Re-emit the line; blank lines preserve SSE event framing.
                    yield line.encode("utf-8") + b"\n"
                if blocked_result is not None:
                    logger.warning(
                        "shadowshield.proxy.stream_cut",
                        decision=blocked_result.decision.value,
                        severity=blocked_result.severity.name,
                        score=round(blocked_result.score, 4),
                    )
                    yield _content_filter_tail(first_chunk)
                    return
                if scan_response:
                    final = await asyncio.to_thread(scanner.finalize)
                    if _is_terminal(final):
                        # Tail text already flowed to the caller; the scan is
                        # still recorded so operators see the near-miss.
                        logger.warning(
                            "shadowshield.proxy.stream_terminal_at_finalize",
                            decision=final.decision.value,
                            severity=final.severity.name,
                            score=round(final.score, 4),
                        )
            finally:
                await stream_cm.__aexit__(None, None, None)

        return StreamingResponse(
            events(), status_code=upstream_response.status_code, media_type=media_type
        )

    async def _handle_chat(request: Request, path: str) -> Any:
        body = await request.body()
        identity = _identity_for(request)
        target = upstream + path
        if request.url.query:
            target += "?" + request.url.query
        payload = _try_json(body.decode("utf-8", errors="replace"))
        if payload is None:
            # Not JSON we can inspect — let the upstream judge it.
            return await _forward_non_stream(request, target, body, identity)
        blocked = await _scan_request_messages(payload, identity)
        if blocked is not None:
            return blocked
        if payload.get("stream") is True:
            return await _forward_stream(request, target, body, identity)
        return await _forward_non_stream(request, target, body, identity)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Any:
        return await _handle_chat(request, "/v1/chat/completions")

    @app.post("/v1/completions")
    async def completions(request: Request) -> Any:
        return await _handle_chat(request, "/v1/completions")

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def passthrough(full_path: str, request: Request) -> Any:
        # Blind forwarding for non-chat endpoints (model lists, embeddings,
        # files). These carry no completion text to guard.
        target = upstream + "/" + full_path
        if request.url.query:
            target += "?" + request.url.query
        body = await request.body()
        upstream_response = await client.request(
            request.method, target, content=body, headers=_forward_headers(request.headers)
        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=_response_headers(upstream_response.headers),
        )

    return app


def serve_proxy(
    upstream: str,
    host: str = "127.0.0.1",
    port: int = 8100,
    mode: str = "balanced",
    *,
    api_keys: list[str] | None = None,
    scan_response: bool = True,
    timeout_seconds: float = 120.0,
) -> None:  # pragma: no cover
    """Run the proxy with uvicorn (used by ``shadowshield proxy``)."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "The proxy requires the 'dashboard' extra: pip install shadowshield[dashboard]"
        ) from exc
    if not resolve_api_keys(api_keys) and not is_loopback(host):
        raise RuntimeError(
            f"refusing to bind unauthenticated proxy to non-loopback host {host}; "
            "set --api-key or SHADOWSHIELD_API_KEY"
        )
    uvicorn.run(
        create_proxy_app(
            Shield.for_mode(mode),
            upstream,
            api_keys=api_keys,
            scan_response=scan_response,
            timeout_seconds=timeout_seconds,
        ),
        host=host,
        port=port,
    )
