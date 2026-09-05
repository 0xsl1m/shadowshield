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

``GET /health`` reports ``status`` plus lightweight request accounting:
``requests_total`` (requests accepted on a proxied route since start-up,
including ones blocked by policy) and ``last_request_at`` (ISO-8601 UTC
timestamp of the most recent one, ``null`` until the first request). Health
probes themselves are not counted, so operators can tell a healthy-but-idle
proxy from one that is actually carrying traffic.

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
import hmac
import json
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
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
from .core.config import Mode
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
_MAX_TEXTS_SCANNED = 128

# The request middleware already caps incoming bodies at one MiB. Apply the
# same bound to successful JSON responses and individual SSE events so an
# upstream cannot make the proxy allocate an unbounded inspection buffer.
_MAX_INSPECTABLE_BODY_BYTES = 1_048_576
_MAX_SSE_EVENT_BYTES = 262_144

_CHAT = "chat"
_ANTHROPIC = "anthropic"
_RESPONSES = "responses"

_TERMINAL = frozenset({Decision.BLOCK, Decision.ESCALATE})


def _is_terminal(result: ScanResult) -> bool:
    return result.decision in _TERMINAL


def _detector_error_count(result: Any) -> int:
    metadata = getattr(result, "metadata", None)
    errors = metadata.get("detector_errors") if isinstance(metadata, dict) else None
    if not isinstance(errors, dict):
        return 0
    return sum(
        value for value in errors.values() if isinstance(value, int) and not isinstance(value, bool)
    )


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
            texts.extend(_chat_tool_texts(message))
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        texts.append(prompt)
    elif isinstance(prompt, list):
        texts.extend(value for value in prompt if isinstance(value, str))
    return texts[:_MAX_TEXTS_SCANNED]


def _chat_tool_texts(container: dict[str, Any]) -> list[str]:
    """Extract current and legacy Chat Completions function arguments."""
    texts: list[str] = []
    function_call = container.get("function_call")
    if isinstance(function_call, dict):
        serialized = _json_payload_text(function_call.get("arguments"))
        if serialized is not None:
            texts.append(serialized)
    tool_calls = container.get("tool_calls")
    if isinstance(tool_calls, list):
        for tool_call in tool_calls[:_MAX_TEXTS_SCANNED]:
            function = tool_call.get("function") if isinstance(tool_call, dict) else None
            if isinstance(function, dict):
                serialized = _json_payload_text(function.get("arguments"))
                if serialized is not None:
                    texts.append(serialized)
    return texts[:_MAX_TEXTS_SCANNED]


def _json_payload_text(value: Any) -> str | None:
    """Serialize a structured tool payload without lossy string coercion."""
    if isinstance(value, str):
        return value
    if not isinstance(value, (dict, list)):
        return None
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError):
        return None


def _anthropic_content_texts(content: Any) -> list[str]:
    """Extract Anthropic text and client/server tool payloads."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return []
    texts: list[str] = []
    for block in content:
        if len(texts) >= _MAX_TEXTS_SCANNED or not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        elif block_type in {"tool_use", "server_tool_use", "mcp_tool_use"}:
            serialized = _json_payload_text(block.get("input"))
            if serialized is not None:
                texts.append(serialized)
        elif block_type in {"tool_result", "mcp_tool_result"}:
            texts.extend(_anthropic_content_texts(block.get("content")))
            texts = texts[:_MAX_TEXTS_SCANNED]
    return texts[:_MAX_TEXTS_SCANNED]


def _anthropic_request_texts(payload: dict[str, Any]) -> list[str]:
    texts = _anthropic_content_texts(payload.get("system"))
    messages = payload.get("messages")
    if isinstance(messages, list):
        for message in messages[:_MAX_MESSAGES_SCANNED]:
            if len(texts) >= _MAX_TEXTS_SCANNED:
                break
            if isinstance(message, dict):
                texts.extend(_anthropic_content_texts(message.get("content")))
                texts = texts[:_MAX_TEXTS_SCANNED]
    return texts


def _openai_item_texts(value: Any, *, depth: int = 0) -> list[str]:
    """Extract Responses API message content and structured tool traffic."""
    if depth > 4:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        texts: list[str] = []
        for item in value:
            if len(texts) >= _MAX_TEXTS_SCANNED:
                break
            texts.extend(_openai_item_texts(item, depth=depth + 1))
            texts = texts[:_MAX_TEXTS_SCANNED]
        return texts
    if not isinstance(value, dict):
        return []

    item_type = value.get("type")
    if item_type in {"input_text", "output_text", "text"}:
        return [value["text"]] if isinstance(value.get("text"), str) else []
    if item_type == "refusal":
        return [value["refusal"]] if isinstance(value.get("refusal"), str) else []
    if item_type in {"message", "input_message", "output_message"}:
        return _openai_item_texts(value.get("content"), depth=depth + 1)
    if item_type is None and isinstance(value.get("role"), str) and "content" in value:
        return _openai_item_texts(value.get("content"), depth=depth + 1)
    if item_type in {"function_call", "mcp_call"}:
        serialized = _json_payload_text(value.get("arguments"))
        return [serialized] if serialized is not None else []
    if item_type == "function_call_output":
        return _openai_item_texts(value.get("output"), depth=depth + 1)
    if item_type in {"custom_tool_call", "custom_tool_call_output"}:
        field = "input" if "input" in value else "output"
        serialized = _json_payload_text(value.get(field))
        return [serialized] if serialized is not None else []
    if item_type in {"computer_call", "shell_call", "local_shell_call"}:
        serialized = _json_payload_text(value.get("action") or value.get("actions"))
        return [serialized] if serialized is not None else []
    return []


def _responses_request_texts(payload: dict[str, Any]) -> list[str]:
    texts = _openai_item_texts(payload.get("instructions"))
    texts.extend(_openai_item_texts(payload.get("input")))
    prompt = payload.get("prompt")
    if isinstance(prompt, dict) and isinstance(prompt.get("variables"), dict):
        for value in prompt["variables"].values():
            if len(texts) >= _MAX_TEXTS_SCANNED:
                break
            texts.extend(_openai_item_texts(value))
    return texts[:_MAX_TEXTS_SCANNED]


def _request_texts(payload: dict[str, Any], protocol: str) -> list[str]:
    if protocol == _ANTHROPIC:
        return _anthropic_request_texts(payload)
    if protocol == _RESPONSES:
        return _responses_request_texts(payload)
    return _message_texts(payload)


def _bounded_content_shape(value: Any, *, depth: int = 0, count: list[int]) -> bool:
    """Check that nested message/content arrays fit the extraction budget."""
    if depth > 4:
        return False
    if isinstance(value, str):
        count[0] += 1
        return count[0] <= _MAX_TEXTS_SCANNED
    if isinstance(value, list):
        if len(value) > _MAX_TEXTS_SCANNED:
            return False
        for item in value:
            if not _bounded_content_shape(item, depth=depth + 1, count=count):
                return False
    elif isinstance(value, dict):
        item_type = value.get("type")
        if item_type in {"input_text", "output_text", "text"}:
            return _bounded_content_shape(value.get("text"), depth=depth + 1, count=count)
        if item_type == "refusal":
            return _bounded_content_shape(value.get("refusal"), depth=depth + 1, count=count)
        if item_type in {"message", "input_message", "output_message"}:
            return _bounded_content_shape(value.get("content"), depth=depth + 1, count=count)
        if item_type is None and isinstance(value.get("role"), str) and "content" in value:
            return _bounded_content_shape(value.get("content"), depth=depth + 1, count=count)
        if item_type in {"tool_use", "server_tool_use", "mcp_tool_use"}:
            if _json_payload_text(value.get("input")) is not None:
                count[0] += 1
            return count[0] <= _MAX_TEXTS_SCANNED
        if item_type in {"tool_result", "mcp_tool_result"}:
            return _bounded_content_shape(value.get("content"), depth=depth + 1, count=count)
        if item_type in {"function_call", "mcp_call"}:
            if _json_payload_text(value.get("arguments")) is not None:
                count[0] += 1
            return count[0] <= _MAX_TEXTS_SCANNED
        if item_type == "function_call_output":
            return _bounded_content_shape(value.get("output"), depth=depth + 1, count=count)
        if item_type in {"custom_tool_call", "custom_tool_call_output"}:
            field = "input" if "input" in value else "output"
            if _json_payload_text(value.get(field)) is not None:
                count[0] += 1
            return count[0] <= _MAX_TEXTS_SCANNED
        if item_type in {"computer_call", "shell_call", "local_shell_call"}:
            if _json_payload_text(value.get("action") or value.get("actions")) is not None:
                count[0] += 1
            return count[0] <= _MAX_TEXTS_SCANNED
    return True


def _bounded_chat_container(container: dict[str, Any], count: list[int]) -> bool:
    if not _bounded_content_shape(container.get("content"), count=count):
        return False
    function_call = container.get("function_call")
    if isinstance(function_call, dict) and not _bounded_content_shape(
        function_call.get("arguments"), count=count
    ):
        return False
    tool_calls = container.get("tool_calls")
    if isinstance(tool_calls, list):
        if len(tool_calls) > _MAX_TEXTS_SCANNED:
            return False
        for tool_call in tool_calls:
            function = tool_call.get("function") if isinstance(tool_call, dict) else None
            if isinstance(function, dict) and not _bounded_content_shape(
                function.get("arguments"), count=count
            ):
                return False
    return True


def _request_extraction_complete(payload: dict[str, Any], protocol: str) -> bool:
    if protocol == _CHAT:
        messages = payload.get("messages")
        if isinstance(messages, list):
            if len(messages) > _MAX_MESSAGES_SCANNED:
                return False
            count = [0]
            messages_complete = all(
                not isinstance(message, dict) or _bounded_chat_container(message, count)
                for message in messages
            )
            return messages_complete and _bounded_content_shape(payload.get("prompt"), count=count)
        return _bounded_content_shape(payload.get("prompt"), count=[0])
    if protocol == _ANTHROPIC:
        messages = payload.get("messages")
        if isinstance(messages, list) and len(messages) > _MAX_MESSAGES_SCANNED:
            return False
        count = [0]
        if not _bounded_content_shape(payload.get("system"), count=count):
            return False
        return not isinstance(messages, list) or all(
            not isinstance(message, dict)
            or _bounded_content_shape(message.get("content"), count=count)
            for message in messages
        )
    count = [0]
    if not _bounded_content_shape(payload.get("instructions"), count=count):
        return False
    if not _bounded_content_shape(payload.get("input"), count=count):
        return False
    prompt = payload.get("prompt")
    variables = prompt.get("variables") if isinstance(prompt, dict) else None
    return not isinstance(variables, dict) or all(
        _bounded_content_shape(value, count=count) for value in variables.values()
    )


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
            if isinstance(message, dict):
                texts.extend(_chat_tool_texts(message))
            if isinstance(choice.get("text"), str):
                texts.append(choice["text"])
    return texts[:_MAX_TEXTS_SCANNED]


def _protocol_response_texts(body: dict[str, Any], protocol: str) -> list[str]:
    if protocol == _ANTHROPIC:
        return _anthropic_content_texts(body.get("content"))
    if protocol == _RESPONSES:
        texts = _openai_item_texts(body.get("output"))
        if isinstance(body.get("output_text"), str):
            texts.append(body["output_text"])
        return texts[:_MAX_TEXTS_SCANNED]
    return _response_texts(body)


def _response_extraction_complete(body: dict[str, Any], protocol: str) -> bool:
    if protocol == _CHAT:
        choices = body.get("choices")
        if not isinstance(choices, list):
            return True
        if len(choices) > _MAX_CHOICES_SCANNED:
            return False
        count = [0]
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict) and not _bounded_chat_container(message, count):
                return False
            if not _bounded_content_shape(choice.get("text"), count=count):
                return False
        return True
    count = [0]
    field = "content" if protocol == _ANTHROPIC else "output"
    if not _bounded_content_shape(body.get(field), count=count):
        return False
    return protocol != _RESPONSES or _bounded_content_shape(body.get("output_text"), count=count)


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
            if isinstance(delta, dict):
                parts.extend(_chat_tool_texts(delta))
            if isinstance(choice.get("text"), str):
                parts.append(choice["text"])
    return "".join(parts)


def _chat_stream_extraction_complete(chunk: dict[str, Any]) -> bool:
    choices = chunk.get("choices")
    if not isinstance(choices, list):
        return True
    if len(choices) > _MAX_CHOICES_SCANNED:
        return False
    count = [0]
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        if isinstance(delta, dict) and not _bounded_chat_container(delta, count):
            return False
        if not _bounded_content_shape(choice.get("text"), count=count):
            return False
    return True


def _protocol_stream_delta_text(event: dict[str, Any], protocol: str) -> str:
    if protocol == _CHAT:
        return _stream_delta_text(event)
    if protocol == _ANTHROPIC:
        if event.get("type") != "content_block_delta":
            return ""
        delta = event.get("delta")
        if not isinstance(delta, dict):
            return ""
        text_delta = delta.get("text")
        if delta.get("type") == "text_delta" and isinstance(text_delta, str):
            return text_delta
        partial_json = delta.get("partial_json")
        if delta.get("type") == "input_json_delta" and isinstance(partial_json, str):
            return partial_json
        return ""
    event_type = event.get("type")
    string_delta_events = {
        "response.output_text.delta",
        "response.refusal.delta",
        "response.function_call_arguments.delta",
        "response.mcp_call_arguments.delta",
        "response.custom_tool_call_input.delta",
        "response.code_interpreter_call_code.delta",
        "response.reasoning_summary_text.delta",
        "response.reasoning_text.delta",
    }
    string_delta = event.get("delta")
    if event_type in string_delta_events and isinstance(string_delta, str):
        return string_delta
    return ""


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


def _blocked_message(result: ScanResult | None, phase: str) -> str:
    decision = result.decision.value if result is not None else "block"
    return f"{phase} blocked by ShadowShield policy (decision={decision})"


def _blocked_error(result: ScanResult | None, phase: str, protocol: str = _CHAT) -> dict[str, Any]:
    """Protocol-native error body without payload content or excerpts."""
    message = _blocked_message(result, phase)
    if protocol == _ANTHROPIC:
        return {
            "type": "error",
            "error": {"type": "permission_error", "message": message},
        }
    return {
        "error": {
            "message": message,
            "type": "content_policy_violation",
            "param": None,
            "code": "shadowshield_blocked",
        }
    }


def _scan_unavailable_error(protocol: str) -> dict[str, Any]:
    message = "ShadowShield security scan unavailable"
    if protocol == _ANTHROPIC:
        return {"type": "error", "error": {"type": "api_error", "message": message}}
    return {
        "error": {
            "message": message,
            "type": "server_error",
            "param": None,
            "code": "shadowshield_scan_unavailable",
        }
    }


def _stream_failure_tail(
    protocol: str,
    result: ScanResult | None,
    first_event: dict[str, Any] | None,
    sequence_number: int,
    *,
    scan_unavailable: bool = False,
) -> bytes:
    """Return the native terminal event for the active streaming protocol."""
    message = (
        "ShadowShield security scan unavailable"
        if scan_unavailable
        else _blocked_message(result, "response")
    )
    error_code = "server_error" if scan_unavailable else "content_policy_violation"
    event: dict[str, Any]
    if protocol == _CHAT:
        if scan_unavailable:
            event = {
                "error": {
                    "message": message,
                    "type": "server_error",
                    "param": None,
                    "code": "shadowshield_scan_unavailable",
                }
            }
            return f"data: {json.dumps(event)}\n\ndata: [DONE]\n\n".encode()
        return _content_filter_tail(first_event)
    if protocol == _ANTHROPIC:
        event = {
            "type": "error",
            "error": {
                "type": "api_error" if scan_unavailable else "permission_error",
                "message": message,
            },
        }
        return f"event: error\ndata: {json.dumps(event)}\n\n".encode()

    # response.failed is the normal terminal event when response.created gave
    # us a complete Response object. Fall back to the Responses API's native
    # error event when an upstream omits or corrupts that opening event.
    response = first_event.get("response") if isinstance(first_event, dict) else None
    if isinstance(response, dict):
        failed_response = dict(response)
        failed_response.update(
            {
                "status": "failed",
                "completed_at": None,
                "error": {"code": error_code, "message": message},
                "output": [],
            }
        )
        event = {
            "type": "response.failed",
            "response": failed_response,
            "sequence_number": sequence_number,
        }
        return f"event: response.failed\ndata: {json.dumps(event)}\n\n".encode()
    event = {
        "type": "error",
        "code": error_code,
        "message": message,
        "param": None,
        "sequence_number": sequence_number,
    }
    return f"event: error\ndata: {json.dumps(event)}\n\n".encode()


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


def _sse_event_end(buffer: bytearray) -> int | None:
    """Return the byte offset after the earliest complete SSE event."""
    ends: list[int] = []
    for separator in (b"\r\n\r\n", b"\n\n", b"\r\r"):
        index = buffer.find(separator)
        if index >= 0:
            ends.append(index + len(separator))
    return min(ends) if ends else None


def _sse_data(frame: bytes) -> str | None:
    """Decode one SSE event's data fields; malformed UTF-8 stays opaque."""
    fields: list[bytes] = []
    for line in frame.splitlines():
        if line == b"data":
            fields.append(b"")
        elif line.startswith(b"data:"):
            value = line[5:]
            if value.startswith(b" "):
                value = value[1:]
            fields.append(value)
    if not fields:
        return None
    try:
        return b"\n".join(fields).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_stream_terminal(data: str | None, event: dict[str, Any] | None, protocol: str) -> bool:
    if protocol == _CHAT:
        return data == "[DONE]"
    if event is None:
        return False
    event_type = event.get("type")
    if protocol == _ANTHROPIC:
        return event_type in {"message_stop", "error"}
    return event_type in {
        "response.completed",
        "response.failed",
        "response.incomplete",
        "error",
    }


_IDENTITY_HMAC_KEY: bytes | None = None


def _identity_hmac_key() -> bytes:
    """Per-process secret for keyed identity fingerprints (not persisted)."""
    global _IDENTITY_HMAC_KEY
    if _IDENTITY_HMAC_KEY is None:
        _IDENTITY_HMAC_KEY = os.urandom(32)
    return _IDENTITY_HMAC_KEY


def _identity_for(request: Any) -> str | None:
    """Stable, non-reversible caller identity for rate limiting.

    HMAC-SHA256 with an ephemeral per-process key: identities stay stable for
    the process lifetime but leaked fingerprints are useless offline.
    """
    supplied = extract_key(request.headers.get("x-api-key"), request.headers.get("authorization"))
    if supplied:
        digest = hmac.new(
            _identity_hmac_key(), supplied.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return "key:" + digest[:16]
    client = getattr(request, "client", None)
    return f"ip:{client.host}" if client is not None else None


def _is_safe_upstream_path(full_path: str) -> bool:
    """Validate the client-controlled suffix appended to the fixed upstream.

    The upstream base URL is operator-configured and constant; the passthrough
    route appends a request-supplied path. Reject anything that could escape
    the upstream's path space or confuse URL parsing downstream (traversal
    segments, backslashes, control characters, embedded userinfo/authority
    tricks). Starlette has already percent-decoded the path at this point.
    """
    if not full_path or "\\" in full_path or "@" in full_path:
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in full_path):
        return False
    return all(segment not in (".", "..") for segment in full_path.split("/"))


def create_proxy_app(
    shield: Shield,
    upstream: str,
    *,
    api_keys: list[str] | None = None,
    include_environment_keys: bool = True,
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
        include_environment_keys: merge ``SHADOWSHIELD_API_KEY`` into explicit
            keys (default on). Disable for an isolated explicit credential.
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

    keys = resolve_api_keys(api_keys, include_environment=include_environment_keys)
    client = httpx.AsyncClient(timeout=timeout_seconds, transport=transport)

    # Request accounting surfaced by /health. Only routes that actually proxy
    # traffic count (chat, completions, passthrough); /health itself does not.
    # Mutated only from coroutines on the event loop, so no lock is needed.
    stats: dict[str, Any] = {"requests_total": 0, "last_request_at": None}

    def _count_request() -> None:
        stats["requests_total"] += 1
        stats["last_request_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

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
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "requests_total": stats["requests_total"],
            "last_request_at": stats["last_request_at"],
        }

    async def _safe_scan(text: str, direction: Direction, identity: str | None) -> Any | None:
        """Scan without allowing exception text or inspected content into logs."""
        try:
            result = await asyncio.to_thread(
                shield.scan, text, direction=direction, identity=identity
            )
        except Exception as exc:
            logger.error(
                "shadowshield.proxy.scan_error",
                direction=direction.value,
                error_type=type(exc).__name__,
            )
            return None
        detector_failures = _detector_error_count(result)
        if detector_failures:
            logger.error(
                "shadowshield.proxy.scan_error",
                direction=direction.value,
                error_type="detector_failure",
                detector_failures=detector_failures,
            )
            if shield.config.mode is not Mode.SHADOW:
                return None
        return result

    def _shadow_log(event: str, result: Any) -> None:
        """Emit shadow data for every non-clean, non-terminal verdict.

        Permissive mode blocks almost nothing by design; without this, the
        signal an operator needs before enforcing (what *would* balanced
        flag/sanitize/block?) is computed and then silently discarded."""
        logger.info(
            event,
            decision=result.decision.value,
            severity=result.severity.name,
            score=round(result.score, 4),
        )

    async def _scan_request_payload(
        payload: dict[str, Any], identity: str | None, protocol: str
    ) -> Any | None:
        """Return a native failure response when request inspection cannot pass."""
        if not scan_request:
            return None
        if not _request_extraction_complete(payload, protocol):
            logger.warning("shadowshield.proxy.request_extraction_limit")
            if shield.config.mode is not Mode.SHADOW:
                return JSONResponse(
                    status_code=403, content=_blocked_error(None, "request", protocol)
                )
        for text in _request_texts(payload, protocol):
            result = await _safe_scan(text, Direction.INPUT, identity)
            if result is None:
                if shield.config.mode is Mode.SHADOW:
                    continue
                return JSONResponse(status_code=503, content=_scan_unavailable_error(protocol))
            if _is_terminal(result) and shield.config.mode is not Mode.SHADOW:
                logger.warning(
                    "shadowshield.proxy.request_blocked",
                    decision=result.decision.value,
                    severity=result.severity.name,
                    score=round(result.score, 4),
                )
                return JSONResponse(
                    status_code=403, content=_blocked_error(result, "request", protocol)
                )
            if result.threats:
                _shadow_log("shadowshield.proxy.request_flagged", result)
        return None

    async def _render_non_stream(
        upstream_response: httpx.Response, identity: str | None, protocol: str
    ) -> Any:
        if scan_response and upstream_response.status_code < 400:
            if len(upstream_response.content) > _MAX_INSPECTABLE_BODY_BYTES:
                logger.warning(
                    "shadowshield.proxy.response_too_large",
                    body_bytes=len(upstream_response.content),
                )
                if shield.config.mode is Mode.SHADOW:
                    prefix = upstream_response.content[:_MAX_INSPECTABLE_BODY_BYTES].decode(
                        "utf-8", errors="replace"
                    )
                    result = await _safe_scan(prefix, Direction.OUTPUT, identity)
                    if result is not None and result.threats:
                        _shadow_log("shadowshield.proxy.response_flagged", result)
                else:
                    return JSONResponse(
                        status_code=403,
                        content=_blocked_error(None, "response", protocol),
                    )
            else:
                parsed = _try_json(upstream_response.text)
                if parsed is None:
                    logger.warning("shadowshield.proxy.response_invalid_json")
                    if shield.config.mode is not Mode.SHADOW:
                        return JSONResponse(
                            status_code=503, content=_scan_unavailable_error(protocol)
                        )
                extraction_limited = parsed is not None and not _response_extraction_complete(
                    parsed, protocol
                )
                if extraction_limited:
                    logger.warning("shadowshield.proxy.response_extraction_limit")
                if extraction_limited and shield.config.mode is not Mode.SHADOW:
                    return JSONResponse(
                        status_code=403,
                        content=_blocked_error(None, "response", protocol),
                    )
                for text in _protocol_response_texts(parsed, protocol) if parsed else ():
                    result = await _safe_scan(text, Direction.OUTPUT, identity)
                    if result is None:
                        if shield.config.mode is Mode.SHADOW:
                            continue
                        return JSONResponse(
                            status_code=503, content=_scan_unavailable_error(protocol)
                        )
                    if _is_terminal(result) and shield.config.mode is not Mode.SHADOW:
                        logger.warning(
                            "shadowshield.proxy.response_blocked",
                            decision=result.decision.value,
                            severity=result.severity.name,
                            score=round(result.score, 4),
                        )
                        return JSONResponse(
                            status_code=403,
                            content=_blocked_error(result, "response", protocol),
                        )
                    if result.threats:
                        _shadow_log("shadowshield.proxy.response_flagged", result)
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=_response_headers(upstream_response.headers),
        )

    async def _forward_non_stream(
        request: Request,
        target: str,
        body: bytes,
        identity: str | None,
        protocol: str,
    ) -> Any:
        upstream_response = await client.request(
            request.method, target, content=body, headers=_forward_headers(request.headers)
        )
        return await _render_non_stream(upstream_response, identity, protocol)

    async def _forward_stream(
        request: Request,
        target: str,
        body: bytes,
        identity: str | None,
        protocol: str,
    ) -> Any:
        # Open the upstream stream eagerly so its status line is known before
        # we commit to our own response status.
        stream_cm = client.stream(
            request.method, target, content=body, headers=_forward_headers(request.headers)
        )
        upstream_response = await stream_cm.__aenter__()
        media_type = upstream_response.headers.get("content-type", "")
        if "text/event-stream" not in media_type:
            try:
                await upstream_response.aread()
                return await _render_non_stream(upstream_response, identity, protocol)
            finally:
                await stream_cm.__aexit__(None, None, None)
        scanner = shield.stream_scanner(
            direction=Direction.OUTPUT,
            identity=identity,
            scan_interval_chars=stream_scan_interval_chars,
            carry_chars=stream_carry_chars,
        )

        async def events() -> AsyncIterator[bytes]:
            first_event: dict[str, Any] | None = None
            sequence_number = 0
            finalized = False
            scanned_item_ids: set[str] = set()
            reported_detector_failure = False

            def detector_scan_failed(result: Any) -> bool:
                nonlocal reported_detector_failure
                detector_failures = _detector_error_count(result)
                if not detector_failures:
                    return False
                if not reported_detector_failure:
                    logger.error(
                        "shadowshield.proxy.scan_error",
                        direction="output",
                        error_type="detector_failure",
                        detector_failures=detector_failures,
                    )
                    reported_detector_failure = True
                return shield.config.mode is not Mode.SHADOW

            async def inspect(frame: bytes) -> tuple[ScanResult | None, bool]:
                """Return (policy result, scan unavailable) for one SSE event."""
                nonlocal first_event, sequence_number, finalized
                data = _sse_data(frame)
                parsed = _try_json(data) if data and data != "[DONE]" else None
                if isinstance(parsed, dict):
                    if (protocol != _RESPONSES and first_event is None) or (
                        protocol == _RESPONSES and parsed.get("type") == "response.created"
                    ):
                        first_event = parsed
                    event_sequence = parsed.get("sequence_number")
                    if isinstance(event_sequence, int) and not isinstance(event_sequence, bool):
                        sequence_number = max(sequence_number, event_sequence)
                if not scan_response:
                    return None, False
                if (
                    isinstance(parsed, dict)
                    and protocol == _CHAT
                    and not _chat_stream_extraction_complete(parsed)
                ):
                    logger.warning("shadowshield.proxy.response_extraction_limit")
                    if shield.config.mode is not Mode.SHADOW:
                        return None, True

                scan_texts: list[str] = []
                delta = (
                    _protocol_stream_delta_text(parsed, protocol)
                    if isinstance(parsed, dict)
                    else ""
                )
                if delta:
                    scan_texts.append(delta)
                    item_id = parsed.get("item_id") if isinstance(parsed, dict) else None
                    if isinstance(item_id, str):
                        scanned_item_ids.add(item_id)
                elif isinstance(parsed, dict) and protocol == _ANTHROPIC:
                    if parsed.get("type") == "content_block_start":
                        scan_texts.extend(_anthropic_content_texts([parsed.get("content_block")]))
                elif isinstance(parsed, dict) and protocol == _RESPONSES:
                    event_type = parsed.get("type")
                    if event_type == "response.output_item.done":
                        item = parsed.get("item")
                        if not _bounded_content_shape(item, count=[0]):
                            logger.warning("shadowshield.proxy.response_extraction_limit")
                            if shield.config.mode is not Mode.SHADOW:
                                return None, True
                        item_id = item.get("id") if isinstance(item, dict) else None
                        if not isinstance(item_id, str) or item_id not in scanned_item_ids:
                            scan_texts.extend(_openai_item_texts(item))
                            if isinstance(item_id, str):
                                scanned_item_ids.add(item_id)
                    elif event_type == "response.completed":
                        response = parsed.get("response")
                        if isinstance(response, dict) and not _response_extraction_complete(
                            response, _RESPONSES
                        ):
                            logger.warning("shadowshield.proxy.response_extraction_limit")
                            if shield.config.mode is not Mode.SHADOW:
                                return None, True
                        output = response.get("output") if isinstance(response, dict) else None
                        if isinstance(output, list):
                            for item in output:
                                item_id = item.get("id") if isinstance(item, dict) else None
                                if isinstance(item_id, str) and item_id in scanned_item_ids:
                                    continue
                                scan_texts.extend(_openai_item_texts(item))
                                if isinstance(item_id, str):
                                    scanned_item_ids.add(item_id)

                for scan_text in scan_texts[:_MAX_TEXTS_SCANNED]:
                    try:
                        terminal = await asyncio.to_thread(scanner.feed, scan_text)
                    except Exception as exc:
                        logger.error(
                            "shadowshield.proxy.scan_error",
                            direction="output",
                            error_type=type(exc).__name__,
                        )
                        return None, shield.config.mode is not Mode.SHADOW
                    current_result = terminal or getattr(scanner, "_worst", None)
                    if detector_scan_failed(current_result):
                        return None, True
                    if terminal is not None and shield.config.mode is not Mode.SHADOW:
                        return terminal, False

                if _is_stream_terminal(data, parsed, protocol):
                    finalized = True
                    try:
                        final = await asyncio.to_thread(scanner.finalize)
                    except Exception as exc:
                        logger.error(
                            "shadowshield.proxy.scan_error",
                            direction="output",
                            error_type=type(exc).__name__,
                        )
                        return None, shield.config.mode is not Mode.SHADOW
                    if detector_scan_failed(final):
                        return None, True
                    if _is_terminal(final) and shield.config.mode is not Mode.SHADOW:
                        return final, False
                    if final.threats:
                        _shadow_log("shadowshield.proxy.response_flagged", final)
                return None, False

            try:
                if upstream_response.status_code >= 400:
                    # Upstream SSE errors are protocol messages, not model output.
                    async for raw in upstream_response.aiter_bytes():
                        yield raw
                    return
                buffer = bytearray()
                oversized_passthrough = False
                async for raw in upstream_response.aiter_bytes():
                    buffer.extend(raw)
                    while True:
                        event_end = _sse_event_end(buffer)
                        if oversized_passthrough:
                            if event_end is None:
                                if len(buffer) > 3:
                                    yield bytes(buffer[:-3])
                                    del buffer[:-3]
                                break
                            yield bytes(buffer[:event_end])
                            del buffer[:event_end]
                            oversized_passthrough = False
                            continue
                        if event_end is None:
                            if len(buffer) > _MAX_SSE_EVENT_BYTES:
                                logger.warning(
                                    "shadowshield.proxy.sse_event_too_large",
                                    body_bytes=len(buffer),
                                )
                                if shield.config.mode is Mode.SHADOW:
                                    if len(buffer) > 3:
                                        yield bytes(buffer[:-3])
                                        del buffer[:-3]
                                    oversized_passthrough = True
                                    break
                                yield _stream_failure_tail(
                                    protocol, None, first_event, sequence_number + 1
                                )
                                return
                            break
                        if event_end > _MAX_SSE_EVENT_BYTES:
                            frame = bytes(buffer[:event_end])
                            del buffer[:event_end]
                            logger.warning(
                                "shadowshield.proxy.sse_event_too_large",
                                body_bytes=len(frame),
                            )
                            if shield.config.mode is Mode.SHADOW:
                                yield frame
                                continue
                            yield _stream_failure_tail(
                                protocol, None, first_event, sequence_number + 1
                            )
                            return
                        frame = bytes(buffer[:event_end])
                        del buffer[:event_end]
                        blocked_result, scan_failed = await inspect(frame)
                        if blocked_result is not None or scan_failed:
                            if blocked_result is not None:
                                logger.warning(
                                    "shadowshield.proxy.stream_cut",
                                    decision=blocked_result.decision.value,
                                    severity=blocked_result.severity.name,
                                    score=round(blocked_result.score, 4),
                                )
                            yield _stream_failure_tail(
                                protocol,
                                blocked_result,
                                first_event,
                                sequence_number + 1,
                                scan_unavailable=scan_failed,
                            )
                            return
                        yield frame

                if buffer:
                    if oversized_passthrough:
                        yield bytes(buffer)
                    else:
                        blocked_result, scan_failed = await inspect(bytes(buffer))
                        if blocked_result is not None or scan_failed:
                            yield _stream_failure_tail(
                                protocol,
                                blocked_result,
                                first_event,
                                sequence_number + 1,
                                scan_unavailable=scan_failed,
                            )
                            return
                        yield bytes(buffer)

                if scan_response and not finalized and not oversized_passthrough:
                    try:
                        final = await asyncio.to_thread(scanner.finalize)
                    except Exception as exc:
                        logger.error(
                            "shadowshield.proxy.scan_error",
                            direction="output",
                            error_type=type(exc).__name__,
                        )
                        if shield.config.mode is not Mode.SHADOW:
                            yield _stream_failure_tail(
                                protocol,
                                None,
                                first_event,
                                sequence_number + 1,
                                scan_unavailable=True,
                            )
                        return
                    if detector_scan_failed(final):
                        yield _stream_failure_tail(
                            protocol,
                            None,
                            first_event,
                            sequence_number + 1,
                            scan_unavailable=True,
                        )
                        return
                    if _is_terminal(final) and shield.config.mode is not Mode.SHADOW:
                        logger.warning(
                            "shadowshield.proxy.stream_terminal_at_finalize",
                            decision=final.decision.value,
                            severity=final.severity.name,
                            score=round(final.score, 4),
                        )
                        yield _stream_failure_tail(
                            protocol, final, first_event, sequence_number + 1
                        )
                    elif final.threats:
                        _shadow_log("shadowshield.proxy.response_flagged", final)
            finally:
                await stream_cm.__aexit__(None, None, None)

        return StreamingResponse(
            events(),
            status_code=upstream_response.status_code,
            headers=_response_headers(upstream_response.headers),
        )

    async def _handle_guarded(request: Request, path: str, protocol: str) -> Any:
        _count_request()
        body = await request.body()
        identity = _identity_for(request)
        target = upstream + path
        if request.url.query:
            target += "?" + request.url.query
        payload = _try_json(body.decode("utf-8", errors="replace"))
        if payload is None:
            logger.warning("shadowshield.proxy.request_invalid_json")
            if shield.config.mode is not Mode.SHADOW:
                return JSONResponse(status_code=503, content=_scan_unavailable_error(protocol))
            # Shadow is an observation lane and preserves uninspectable traffic.
            return await _forward_non_stream(request, target, body, identity, protocol)
        blocked = await _scan_request_payload(payload, identity, protocol)
        if blocked is not None:
            return blocked
        if payload.get("stream") is True:
            return await _forward_stream(request, target, body, identity, protocol)
        return await _forward_non_stream(request, target, body, identity, protocol)

    @app.post("/v1/chat/completions/", include_in_schema=False)
    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Any:
        return await _handle_guarded(request, request.url.path, _CHAT)

    @app.post("/v1/completions/", include_in_schema=False)
    @app.post("/v1/completions")
    async def completions(request: Request) -> Any:
        return await _handle_guarded(request, request.url.path, _CHAT)

    @app.post("/v1/messages/", include_in_schema=False)
    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Any:
        return await _handle_guarded(request, request.url.path, _ANTHROPIC)

    @app.post("/v1/responses/", include_in_schema=False)
    @app.post("/v1/responses")
    async def openai_responses(request: Request) -> Any:
        return await _handle_guarded(request, request.url.path, _RESPONSES)

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def passthrough(full_path: str, request: Request) -> Any:
        # Blind forwarding for non-chat endpoints (model lists, embeddings,
        # files). These carry no completion text to guard. The path suffix is
        # client-controlled; validate it so it cannot escape the configured
        # upstream's path space.
        if not _is_safe_upstream_path(full_path):
            return Response(status_code=400, content=b'{"error":{"message":"invalid path"}}')
        _count_request()
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
