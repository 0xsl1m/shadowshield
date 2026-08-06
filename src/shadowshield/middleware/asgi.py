"""Pure-ASGI guardrail middleware — guardrails without a separate proxy process.

Wrap any ASGI app (FastAPI, Starlette, Django ASGI, a raw handler) so JSON
chat-completion traffic on the protected prefixes is scanned in both
directions:

- **Request**: ``messages`` / ``prompt`` text is scanned (INPUT direction) before
  the downstream app sees it. A BLOCK decision short-circuits with a JSON
  ``403``; the app is never called.
- **Response**: non-streaming JSON completions are buffered (bounded) and the
  ``choices`` text is scanned (OUTPUT direction); a BLOCK decision replaces the
  response with the same JSON ``403`` shape — offending content never leaves
  the process.
- **SSE streams** (``text/event-stream``) pass through unmodified: mid-stream
  cutting needs chunked scanning, which is what the standalone reverse proxy
  (:mod:`shadowshield.proxy`) is for.

No FastAPI/Starlette import — this module works with any ASGI framework.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from .._security import MAX_HTTP_BODY_BYTES, MAX_HTTP_BODY_FRAMES
from ..core.shield import Shield
from ..core.types import ScanResult
from .base import message_text

_MAX_MESSAGES_SCANNED = 128
_MAX_CHOICES_SCANNED = 16


def _request_texts(payload: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    messages = payload.get("messages")
    if isinstance(messages, list):
        for message in messages[:_MAX_MESSAGES_SCANNED]:
            text = message_text(message)
            if text:
                texts.append(text)
    prompt = payload.get("prompt")
    if isinstance(prompt, str) and prompt:
        texts.append(prompt)
    return texts


def _choice_texts(payload: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    choices = payload.get("choices")
    if isinstance(choices, list):
        for choice in choices[:_MAX_CHOICES_SCANNED]:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict):
                text = message_text(message)
                if text:
                    texts.append(text)
            if isinstance(choice.get("text"), str) and choice["text"]:
                texts.append(choice["text"])
    return texts


def _error_body(result: ScanResult, phase: str) -> bytes:
    return json.dumps(
        {
            "error": {
                "message": (
                    f"{phase} blocked by ShadowShield policy (decision={result.decision.value})"
                ),
                "type": "content_policy_violation",
                "param": None,
                "code": "shadowshield_blocked",
            }
        }
    ).encode()


async def _send_json(send: Any, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class ShieldASGIMiddleware:
    """Guard OpenAI-shaped JSON traffic on ``protected_prefixes``.

    Args:
        app: the downstream ASGI app.
        shield: the :class:`Shield` to enforce.
        protected_prefixes: path prefixes that carry chat traffic.
        max_body_bytes: hard cap for buffered request/response bodies.
        scan_requests / scan_responses: per-direction kill-switches.
        block_status: HTTP status returned when a scan blocks (default 403).
        identity: stable identity forwarded to the engine for rate limiting
            (per-deployment, e.g. a tenant id — the ASGI scope has no auth
            context of its own).
    """

    def __init__(
        self,
        app: Any,
        shield: Shield,
        *,
        protected_prefixes: tuple[str, ...] = ("/v1/chat/completions", "/v1/completions"),
        max_body_bytes: int = MAX_HTTP_BODY_BYTES,
        scan_requests: bool = True,
        scan_responses: bool = True,
        block_status: int = 403,
        identity: str | None = None,
    ) -> None:
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be greater than zero")
        self.app = app
        self.shield = shield
        self.protected_prefixes = protected_prefixes
        self.max_body_bytes = max_body_bytes
        self.scan_requests = scan_requests
        self.scan_responses = scan_responses
        self.block_status = block_status
        self.identity = identity

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = str(scope.get("path", ""))
        protected = any(path.startswith(prefix) for prefix in self.protected_prefixes)
        if scope.get("type") != "http" or not protected:
            await self.app(scope, receive, send)
            return

        body = bytearray()
        frames = 0
        while True:
            message = dict(await receive())
            if message.get("type") != "http.request":
                break
            frames += 1
            body.extend(message.get("body", b""))
            if frames > MAX_HTTP_BODY_FRAMES or len(body) > self.max_body_bytes:
                await _send_json(send, 413, b'{"detail":"request body too large"}')
                return
            if not message.get("more_body", False):
                break
        payload_bytes = bytes(body)

        payload: dict[str, Any] | None = None
        if payload_bytes:
            try:
                parsed = json.loads(payload_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
            payload = parsed if isinstance(parsed, dict) else None

        if payload is not None and self.scan_requests:
            for text in _request_texts(payload):
                result = await asyncio.to_thread(
                    self.shield.scan, text, direction="input", identity=self.identity
                )
                if result.blocked:
                    await _send_json(send, self.block_status, _error_body(result, "request"))
                    return

        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": payload_bytes, "more_body": False}
            # After the buffered body, delegate so disconnect listeners work.
            message = await receive()
            return dict(message) if isinstance(message, dict) else {"type": "http.disconnect"}

        await self.app(scope, replay_receive, self._wrap_send(send))

    # ------------------------------------------------------------------ #
    def _wrap_send(self, send: Any) -> Any:
        response_start: dict[str, Any] | None = None
        buffering = False
        overflow = False
        buf = bytearray()

        async def send_wrapper(message: dict[str, Any]) -> None:
            nonlocal response_start, buffering, overflow
            if message.get("type") == "http.response.start":
                headers = {
                    k.lower(): v for k, v in message.get("headers", []) if isinstance(k, bytes)
                }
                content_type = headers.get(b"content-type", b"").decode("latin-1")
                buffering = (
                    self.scan_responses
                    and int(message.get("status", 500)) < 400
                    and "json" in content_type
                    # SSE streams pass through; see module docstring.
                    and "text/event-stream" not in content_type
                )
                if buffering:
                    response_start = message
                else:
                    await send(message)
                return
            if message.get("type") != "http.response.body":
                await send(message)
                return
            if not buffering:
                await send(message)
                return

            chunk = message.get("body", b"")
            buf.extend(chunk)
            if len(buf) > self.max_body_bytes:
                # Response grew past the scan budget: flush verbatim, unguarded.
                overflow = True
                buffering = False
                assert response_start is not None
                await send(response_start)
                await send(
                    {
                        "type": "http.response.body",
                        "body": bytes(buf),
                        "more_body": message.get("more_body", False),
                    }
                )
                return
            if message.get("more_body", False):
                return

            buffering = False
            assert response_start is not None
            try:
                parsed = json.loads(bytes(buf))
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                for text in _choice_texts(parsed):
                    result = await asyncio.to_thread(
                        self.shield.scan, text, direction="output", identity=self.identity
                    )
                    if result.blocked:
                        await _send_json(send, self.block_status, _error_body(result, "response"))
                        return
            await send(response_start)
            await send({"type": "http.response.body", "body": bytes(buf), "more_body": False})

        async def guarded_send(message: dict[str, Any]) -> None:
            if overflow:  # once flushed, everything else passes through
                await send(message)
                return
            await send_wrapper(message)

        return guarded_send
