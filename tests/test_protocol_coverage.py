"""Synthetic, content-free protocol-boundary regression coverage.

These tests use an in-memory ASGI app and ``httpx.MockTransport`` only.  The
marker is caught by a purpose-built detector, which makes the cases independent
of detector heuristics and proves that each wire-format field reached the
scanner.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

import shadowshield as ss
import shadowshield.proxy as proxy_module
from shadowshield.core.types import Severity, Threat, ThreatCategory
from shadowshield.detectors.base import Detector, ScanContext
from shadowshield.proxy import create_proxy_app
from shadowshield.proxy_coverage import StreamProtocolExtractor

pytest.importorskip("fastapi")

_MARKER = "__synthetic_protocol_marker__"
_OPAQUE_ID = "synthetic-provider-id"


@pytest.fixture(autouse=True)
def _remove_ambient_proxy_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep these hermetic; no machine credential can turn the proxy on."""
    monkeypatch.delenv("SHADOWSHIELD_API_KEY", raising=False)


class _LogSpy:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def _record(self, event: str, **kwargs: Any) -> None:
        self.entries.append({"event": event, **kwargs})

    info = _record
    warning = _record
    error = _record


@pytest.fixture(autouse=True)
def _capture_coverage_logs(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Make every receipt an observation of the proxy, never a test verdict."""
    logs = _LogSpy()
    monkeypatch.setattr(proxy_module, "logger", logs)
    request.node._synthetic_coverage_logs = logs.entries  # type: ignore[attr-defined]
    yield


class _MarkerDetector(Detector):
    """A deterministic detector which records only count/direction metadata."""

    name = "synthetic_marker_detector"

    def __init__(self) -> None:
        self.scans: list[str] = []

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        self.scans.append(context.direction.value)
        if _MARKER not in text:
            return []
        return [
            Threat(
                category=ThreatCategory.UNKNOWN,
                severity=Severity.CRITICAL,
                score=1.0,
                detector=self.name,
                message="synthetic marker observed",
            )
        ]


class _FailingDetector(Detector):
    name = "synthetic_failing_detector"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        raise RuntimeError(_MARKER)


class _Fragments(httpx.AsyncByteStream):
    def __init__(self, fragments: list[bytes]) -> None:
        self._fragments = fragments

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for fragment in self._fragments:
            yield fragment

    async def aclose(self) -> None:
        return None


class _Upstream:
    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        response = self.responses.get(request.url.path)
        if response is None:
            return httpx.Response(404, json={"error": "missing synthetic response"})
        return response


def _shield(mode: str = "balanced", *, failing: bool = False) -> tuple[ss.Shield, _MarkerDetector]:
    marker = _MarkerDetector()
    detectors: list[Detector] = [marker]
    if failing:
        detectors.append(_FailingDetector())
    return ss.Shield.for_mode(mode, extra_detectors=detectors), marker


def _app(upstream: _Upstream, shield: ss.Shield) -> Any:
    return create_proxy_app(
        shield,
        "http://synthetic-upstream.test",
        stream_scan_interval_chars=1,
        transport=upstream.transport,
    )


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test")


def _event(event: str, payload: dict[str, Any], newline: bytes = b"\n") -> bytes:
    return (
        b"event: "
        + event.encode()
        + newline
        + b"data: "
        + json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        + newline
        + newline
    )


def _receipt(
    request: pytest.FixtureRequest,
    *,
    protocol: str,
    boundary: str,
    transport: str | None = None,
    status: str | None = None,
) -> None:
    """Optionally write a fixed-schema receipt with no inspected material.

    The output path is deliberately opt-in so ordinary test runs do not create
    artifacts.  Values are enumerated constants apart from pytest's static node
    id; payload bytes, provider IDs, exception text, hashes, and event labels
    are never persisted.
    """
    logs = getattr(request.node, "_synthetic_coverage_logs", [])
    events = [
        entry
        for entry in logs
        if entry.get("event") == "shadowshield.proxy.coverage"
        and entry.get("protocol") == protocol
        and entry.get("phase") == boundary
        and (transport is None or entry.get("transport") == transport)
    ]
    assert events, "proxy emitted no coverage receipt"
    observed = events[-1]
    expected = {
        "event",
        "schema",
        "protocol",
        "phase",
        "transport",
        "status",
        "reason",
        "text_units_discovered",
        "text_units_scanned",
        "opaque_units",
        "media_units",
        "reference_units",
        "malformed_units",
        "scanner_errors",
        "budget_exceeded",
        "terminal_seen",
    }
    assert set(observed) == expected
    assert observed["schema"] == "shadowshield.proxy.coverage.v1"
    assert observed["protocol"] == protocol
    assert observed["phase"] == boundary
    assert observed["transport"] in {"json", "sse"}
    assert observed["status"] in {"full", "partial", "unscanned", "failed"}
    if status is not None:
        assert observed["status"] == status
    assert observed["reason"] in {
        "complete",
        "disabled",
        "invalid_json",
        "invalid_utf8",
        "unknown_shape",
        "budget_exceeded",
        "malformed_event",
        "event_too_large",
        "scanner_error",
        "detector_error",
        "upstream_error",
        "stream_incomplete",
    }
    assert all(
        isinstance(observed[name], int) and observed[name] >= 0
        for name in (
            "text_units_discovered",
            "text_units_scanned",
            "opaque_units",
            "media_units",
            "reference_units",
            "malformed_units",
            "scanner_errors",
        )
    )
    assert isinstance(observed["budget_exceeded"], bool)
    assert isinstance(observed["terminal_seen"], bool)
    destination = os.environ.get("SHADOWSHIELD_SYNTHETIC_RECEIPTS")
    if not destination:
        return
    record = {"test_nodeid": request.node.nodeid.split("[", 1)[0]}
    record.update({name: observed[name] for name in expected})
    with Path(destination).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def _claude_payload(field: str) -> dict[str, Any]:
    content: Any
    if field == "system":
        return {"model": "claude-synthetic", "max_tokens": 8, "system": _MARKER, "messages": []}
    if field == "text":
        content = [{"type": "text", "text": _MARKER}]
    elif field == "thinking":
        content = [{"type": "thinking", "thinking": _MARKER}]
    elif field == "tool_input":
        content = [{"type": "tool_use", "name": "x", "id": _OPAQUE_ID, "input": {"x": _MARKER}}]
    elif field == "server_tool_input":
        content = [
            {"type": "server_tool_use", "name": "x", "id": _OPAQUE_ID, "input": {"x": _MARKER}}
        ]
    else:
        content = [
            {
                "type": "tool_result",
                "tool_use_id": _OPAQUE_ID,
                "content": [{"type": "text", "text": _MARKER}],
            }
        ]
    return {
        "model": "claude-synthetic",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": content}],
    }


@pytest.mark.parametrize(
    "field", ["system", "text", "thinking", "tool_input", "server_tool_input", "tool_result"]
)
async def test_claude_request_variants_reach_scanner(
    request: pytest.FixtureRequest, field: str
) -> None:
    upstream = _Upstream({"/v1/messages": httpx.Response(200, json={"content": []})})
    shield, marker = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post("/v1/messages", json=_claude_payload(field))
    assert response.status_code == 403
    assert upstream.calls == []
    assert marker.scans == ["input"]
    _receipt(request, protocol="anthropic", boundary="request")


@pytest.mark.parametrize(
    "field,value",
    [
        ("instructions", _MARKER),
        ("input_text", {"type": "input_text", "text": _MARKER}),
        ("function_arguments", {"type": "function_call", "name": "x", "arguments": {"x": _MARKER}}),
        (
            "function_output",
            {"type": "function_call_output", "call_id": _OPAQUE_ID, "output": _MARKER},
        ),
    ],
)
async def test_openai_responses_request_variants_reach_scanner(
    request: pytest.FixtureRequest, field: str, value: Any
) -> None:
    payload: dict[str, Any] = {"model": "gpt-synthetic", "input": "clean"}
    if field == "instructions":
        payload["instructions"] = value
    else:
        payload["input"] = [value]
    upstream = _Upstream({"/v1/responses": httpx.Response(200, json={"output": []})})
    shield, marker = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post("/v1/responses", json=payload)
    assert response.status_code == 403
    assert upstream.calls == []
    assert marker.scans == ["input"]
    _receipt(request, protocol="responses", boundary="request")


@pytest.mark.parametrize(
    "item",
    [
        {"type": "message", "content": [{"type": "output_text", "text": _MARKER}]},
        {"type": "message", "content": [{"type": "refusal", "refusal": _MARKER}]},
        {"type": "function_call", "name": "x", "arguments": {"x": _MARKER}},
        {"type": "function_call_output", "call_id": _OPAQUE_ID, "output": _MARKER},
        {
            "type": "shell_call",
            "action": {"command": "clean"},
            "output": {"stdout": _MARKER, "stderr": _MARKER},
        },
        {"type": "mcp_call", "name": "x", "arguments": {"x": "clean"}, "output": _MARKER},
        {"type": "reasoning", "summary": [{"type": "summary_text", "text": _MARKER}]},
    ],
)
async def test_openai_responses_output_variants_reach_scanner(
    request: pytest.FixtureRequest, item: dict[str, Any]
) -> None:
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200, json={"id": _OPAQUE_ID, "status": "completed", "output": [item]}
            )
        }
    )
    shield, marker = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean"}
        )
    assert response.status_code == 403
    assert _MARKER not in response.text
    assert marker.scans.count("input") == 1
    assert marker.scans.count("output") >= 1
    _receipt(request, protocol="responses", boundary="response")


async def test_shadow_stream_preserves_fragmented_openai_bytes_and_emits_content_free_receipt(
    request: pytest.FixtureRequest,
) -> None:
    completed = {
        "type": "response.completed",
        "response": {
            "id": _OPAQUE_ID,
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": _MARKER + " café"}]}
            ],
        },
    }
    raw = _event("response.completed", completed, b"\r")
    fragments = [raw[:17], raw[17:39], raw[39:-3], raw[-3:]]
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200, headers={"content-type": "text/event-stream"}, stream=_Fragments(fragments)
            )
        }
    )
    shield, marker = _shield("shadow")
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean", "stream": True}
        )
    assert response.status_code == 200
    assert response.content == raw
    assert marker.scans.count("input") == 1
    assert marker.scans.count("output") >= 1
    logged = json.dumps(getattr(request.node, "_synthetic_coverage_logs", []), sort_keys=True)
    assert _MARKER not in logged and _OPAQUE_ID not in logged and "output_text" not in logged
    _receipt(request, protocol="responses", boundary="response")


async def test_shadow_scanner_error_preserves_claude_stream_without_content_leak(
    request: pytest.FixtureRequest,
) -> None:
    raw = _event(
        "content_block_delta",
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": _MARKER}},
        b"\r\n",
    )
    upstream = _Upstream(
        {
            "/v1/messages": httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Fragments([raw[:9], raw[9:]]),
            )
        }
    )
    shield, _ = _shield("shadow", failing=True)
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/messages",
            json={
                "model": "claude-synthetic",
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "clean"}],
                "stream": True,
            },
        )
    assert response.status_code == 200
    assert response.content == raw
    assert b"content_filter" not in response.content and b"scan_unavailable" not in response.content
    logged = json.dumps(getattr(request.node, "_synthetic_coverage_logs", []), sort_keys=True)
    assert _MARKER not in logged and _OPAQUE_ID not in logged and "RuntimeError" not in logged
    _receipt(request, protocol="anthropic", boundary="response")


async def test_responses_stream_scans_unseen_done_snapshot_after_same_item_delta(
    request: pytest.FixtureRequest,
) -> None:
    """A clean delta must not make a later same-ID snapshot trusted by identity."""
    created = {"type": "response.created", "response": {"id": _OPAQUE_ID, "output": []}}
    clean_delta = {"type": "response.output_text.delta", "item_id": "shared-item", "delta": "clean"}
    done = {
        "type": "response.output_item.done",
        "item": {
            "id": "shared-item",
            "type": "message",
            "content": [{"type": "output_text", "text": _MARKER}],
        },
    }
    raw = b"".join(
        (
            _event("response.created", created, b"\r\n"),
            _event("response.output_text.delta", clean_delta, b"\r\n"),
            _event("response.output_item.done", done, b"\r\n"),
        )
    )
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Fragments([raw[:29], raw[29:71], raw[71:]]),
            )
        }
    )
    shield, marker = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean", "stream": True}
        )
    assert response.status_code == 200
    assert _MARKER not in response.text
    assert b"response.failed" in response.content
    assert marker.scans.count("output") >= 2
    _receipt(request, protocol="responses", boundary="response")


async def test_shadow_json_request_and_response_preserve_raw_utf8_bytes(
    request: pytest.FixtureRequest,
) -> None:
    raw_request = json.dumps(
        {
            "model": "claude-synthetic",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": _MARKER + " café"}],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    raw_response = json.dumps(
        {"id": _OPAQUE_ID, "content": [{"type": "text", "text": _MARKER + " café"}]},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    upstream = _Upstream(
        {
            "/v1/messages": httpx.Response(
                200, headers={"content-type": "application/json"}, content=raw_response
            )
        }
    )
    shield, _ = _shield("shadow")
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/messages", content=raw_request, headers={"content-type": "application/json"}
        )
    assert response.status_code == 200
    assert upstream.calls[0].content == raw_request
    assert response.content == raw_response
    _receipt(request, protocol="anthropic", boundary="response")


@pytest.mark.parametrize(
    ("path", "protocol", "request_body", "response_body"),
    [
        (
            "/v1/messages",
            "anthropic",
            {
                "model": "claude-synthetic",
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "clean"}],
            },
            {"id": "clean", "content": [{"type": "text", "text": "clean"}]},
        ),
        (
            "/v1/responses",
            "responses",
            {
                "model": "gpt-synthetic",
                "instructions": "clean",
                "input": [{"type": "input_text", "text": "clean"}],
            },
            {
                "id": "clean",
                "status": "completed",
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "clean"}]}
                ],
            },
        ),
    ],
)
async def test_clean_json_receipts_are_full_in_both_directions(
    request: pytest.FixtureRequest,
    path: str,
    protocol: str,
    request_body: dict[str, Any],
    response_body: dict[str, Any],
) -> None:
    upstream = _Upstream({path: httpx.Response(200, json=response_body)})
    shield, marker = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=request_body)
    assert response.status_code == 200
    assert len(upstream.calls) == 1
    assert marker.scans.count("input") >= 1 and marker.scans.count("output") >= 1
    _receipt(request, protocol=protocol, boundary="request", transport="json", status="full")
    _receipt(request, protocol=protocol, boundary="response", transport="json", status="full")


@pytest.mark.parametrize(
    ("protocol", "path", "payload"),
    [
        (
            "anthropic",
            "/v1/messages",
            {
                "model": "claude-synthetic",
                "max_tokens": 8,
                "messages": [
                    {"role": "user", "content": [{"type": "future_block", "value": "unscanned"}]}
                ],
            },
        ),
        (
            "responses",
            "/v1/responses",
            {"model": "gpt-synthetic", "input": [{"type": "future_item", "value": "unscanned"}]},
        ),
        (
            "responses",
            "/v1/responses",
            {"model": "gpt-synthetic", "previous_response_id": _OPAQUE_ID, "input": "clean"},
        ),
    ],
)
async def test_unknown_or_retained_request_context_never_receives_full_coverage(
    request: pytest.FixtureRequest, protocol: str, path: str, payload: dict[str, Any]
) -> None:
    upstream = _Upstream({path: httpx.Response(200, json={"output": []})})
    shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=payload)
    assert response.status_code in {200, 403, 503}
    _receipt(request, protocol=protocol, boundary="request", transport="json")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage" and entry.get("phase") == "request"
    ][-1]
    assert event["status"] != "full"
    if "previous_response_id" in payload:
        assert response.status_code == 200
        assert event["reference_units"] >= 1
    else:
        assert upstream.calls == []


@pytest.mark.parametrize(
    "path,protocol", [("/v1/messages", "anthropic"), ("/v1/responses", "responses")]
)
async def test_invalid_utf8_request_is_not_silently_counted_clean(
    request: pytest.FixtureRequest, path: str, protocol: str
) -> None:
    upstream = _Upstream({path: httpx.Response(200, json={"output": []})})
    shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            path, content=b'{"input":"\xff"}', headers={"content-type": "application/json"}
        )
    assert response.status_code == 503
    assert upstream.calls == []
    _receipt(request, protocol=protocol, boundary="request", transport="json")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage" and entry.get("phase") == "request"
    ][-1]
    assert event["status"] != "full" and event["reason"] in {"invalid_utf8", "invalid_json"}


async def test_claude_thinking_and_server_tool_delta_streams_are_scanned(
    request: pytest.FixtureRequest,
) -> None:
    thinking = {
        "type": "content_block_delta",
        "delta": {"type": "thinking_delta", "thinking": "clean"},
    }
    tool = {
        "type": "content_block_delta",
        "delta": {"type": "input_json_delta", "partial_json": json.dumps({"x": _MARKER})},
    }
    raw = _event("content_block_delta", thinking, b"\r\n") + _event(
        "content_block_delta", tool, b"\n"
    )
    upstream = _Upstream(
        {
            "/v1/messages": httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Fragments([raw[:23], raw[23:]]),
            )
        }
    )
    shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/messages",
            json={
                "model": "claude-synthetic",
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "clean"}],
                "stream": True,
            },
        )
    assert response.status_code == 200
    assert _MARKER not in response.text
    assert b"permission_error" in response.content
    _receipt(request, protocol="anthropic", boundary="response", transport="sse")


@pytest.mark.parametrize(
    ("path", "protocol", "events", "terminal"),
    [
        (
            "/v1/responses",
            "responses",
            [
                {
                    "type": "response.function_call_arguments.delta",
                    "item_id": "tool-a",
                    "delta": '{"x":"\\u005f\\u005fsynthetic_',
                },
                {
                    "type": "response.function_call_arguments.delta",
                    "item_id": "tool-b",
                    "delta": '{"x":"clean"}',
                },
                {
                    "type": "response.function_call_arguments.delta",
                    "item_id": "tool-a",
                    "delta": 'protocol_marker__"}',
                },
            ],
            b"content_policy_violation",
        ),
        (
            "/v1/messages",
            "anthropic",
            [
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": '{"x":"\\u005f\\u005fsynthetic_',
                    },
                },
                {
                    "type": "content_block_delta",
                    "index": 1,
                    "delta": {"type": "input_json_delta", "partial_json": '{"x":"clean"}'},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": 'protocol_marker__"}'},
                },
            ],
            b"permission_error",
        ),
    ],
)
async def test_interleaved_tool_json_channels_reconstruct_unicode_marker_before_forwarding_final_frame(
    request: pytest.FixtureRequest,
    path: str,
    protocol: str,
    events: list[dict[str, Any]],
    terminal: bytes,
) -> None:
    raw = b"".join(
        _event(event["type"], event, b"\r\n" if index % 2 == 0 else b"\n")
        for index, event in enumerate(events)
    )
    upstream = _Upstream(
        {
            path: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Fragments([raw[:19], raw[19:71], raw[71:]]),
            )
        }
    )
    shield, _ = _shield()
    body = {"model": "gpt-synthetic", "input": "clean", "stream": True}
    if protocol == "anthropic":
        body = {
            "model": "claude-synthetic",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "clean"}],
            "stream": True,
        }
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 200
    assert _MARKER not in response.text
    assert terminal in response.content
    final_frame = _event(events[-1]["type"], events[-1], b"\r\n" if len(events) % 2 else b"\n")
    assert final_frame not in response.content
    _receipt(request, protocol=protocol, boundary="response", transport="sse")


@pytest.mark.parametrize(
    ("protocol", "path", "raw"),
    [
        (
            "responses",
            "/v1/responses",
            b"event: response.output_item.done\r\ndata: {not-json}\r\n\r\n",
        ),
        ("anthropic", "/v1/messages", b"event: content_block_stop\rdata: {not-json}\r\r"),
    ],
)
async def test_shadow_malformed_or_unknown_sse_is_exact_and_receipt_is_nonfull(
    request: pytest.FixtureRequest, protocol: str, path: str, raw: bytes
) -> None:
    upstream = _Upstream(
        {
            path: httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Fragments([raw[:7], raw[7:]]),
            )
        }
    )
    shield, _ = _shield("shadow")
    body: dict[str, Any] = {"model": "gpt-synthetic", "input": "clean", "stream": True}
    if protocol == "anthropic":
        body = {"model": "claude-synthetic", "max_tokens": 8, "messages": [], "stream": True}
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 200 and response.content == raw
    _receipt(request, protocol=protocol, boundary="response", transport="sse")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage"
    ][-1]
    assert event["status"] != "full" and event["malformed_units"] >= 1


async def test_shadow_inline_media_and_budget_limits_are_not_counted_full(
    request: pytest.FixtureRequest,
) -> None:
    items = [{"type": "input_text", "text": "clean"} for _ in range(129)]
    items[0] = {"type": "input_text", "text": _MARKER}
    items[1] = {"type": "input_image", "file_data": "opaque-inline"}
    raw = json.dumps({"model": "gpt-synthetic", "input": items}, separators=(",", ":")).encode()
    upstream = _Upstream({"/v1/responses": httpx.Response(200, json={"output": []})})
    shield, marker = _shield("shadow")
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", content=raw, headers={"content-type": "application/json"}
        )
    assert response.status_code == 200 and upstream.calls[0].content == raw
    assert marker.scans.count("input") >= 1
    _receipt(request, protocol="responses", boundary="request", transport="json")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage" and entry.get("phase") == "request"
    ][-1]
    assert event["status"] != "full" and event["budget_exceeded"] and event["media_units"] >= 1


async def test_shadow_max_input_prefix_truncation_is_nonfull_but_preserves_request(
    request: pytest.FixtureRequest,
) -> None:
    raw = json.dumps(
        {"model": "gpt-synthetic", "input": _MARKER + ("x" * 128)}, separators=(",", ":")
    ).encode()
    upstream = _Upstream({"/v1/responses": httpx.Response(200, json={"output": []})})
    shield = ss.Shield(
        ss.ShieldConfig.for_mode("shadow", max_input_chars=8), extra_detectors=[_MarkerDetector()]
    )
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", content=raw, headers={"content-type": "application/json"}
        )
    assert response.status_code == 200 and upstream.calls[0].content == raw
    _receipt(request, protocol="responses", boundary="request", transport="json")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage" and entry.get("phase") == "request"
    ][-1]
    assert event["status"] != "full" and event["text_units_scanned"] >= 1


@pytest.mark.parametrize(
    ("path", "protocol", "raw"),
    [
        (
            "/v1/responses",
            "responses",
            b'{"output":' + (b"[" * 3000) + b'"x"' + (b"]" * 3000) + b"}",
        ),
        (
            "/v1/messages",
            "anthropic",
            b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"\\ud800"}}\n\n',
        ),
    ],
)
async def test_shadow_deep_or_surrogate_payload_preserves_raw_bytes_without_500(
    request: pytest.FixtureRequest, path: str, protocol: str, raw: bytes
) -> None:
    headers = (
        {"content-type": "text/event-stream"}
        if path.endswith("messages")
        else {"content-type": "application/json"}
    )
    upstream = _Upstream({path: httpx.Response(200, headers=headers, content=raw)})
    shield, _ = _shield("shadow")
    body: dict[str, Any] = {
        "model": "gpt-synthetic",
        "input": "clean",
        "stream": path.endswith("messages"),
    }
    if protocol == "anthropic":
        body = {"model": "claude-synthetic", "max_tokens": 8, "messages": [], "stream": True}
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 200 and response.content == raw
    _receipt(
        request,
        protocol=protocol,
        boundary="response",
        transport="sse" if path.endswith("messages") else "json",
    )


async def test_responses_failure_tail_never_echoes_created_metadata(
    request: pytest.FixtureRequest,
) -> None:
    created = {
        "type": "response.created",
        "response": {
            "id": _OPAQUE_ID,
            "model": "gpt-synthetic",
            "metadata": {"leak": _MARKER},
            "output": [],
        },
    }
    delta = {"type": "response.output_text.delta", "item_id": "x", "delta": _MARKER}
    raw = _event("response.created", created) + _event("response.output_text.delta", delta)
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200, headers={"content-type": "text/event-stream"}, content=raw
            )
        }
    )
    shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean", "stream": True}
        )
    tail = response.content.split(b"event: response.failed", 1)[1]
    assert (
        b"response.failed" in response.content
        and _MARKER.encode() not in tail
        and _OPAQUE_ID.encode() not in tail
    )
    _receipt(request, protocol="responses", boundary="response", transport="sse")


@pytest.mark.parametrize("protocol", ["anthropic", "responses"])
@pytest.mark.parametrize("mode", ["balanced", "shadow"])
async def test_large_delta_prefix_is_scanned_and_shadow_cap_is_reported(
    request: pytest.FixtureRequest, protocol: str, mode: str
) -> None:
    text = _MARKER + "x" * 10_000
    if protocol == "anthropic":
        path = "/v1/messages"
        body = {"messages": [{"role": "user", "content": "clean"}], "stream": True}
        delta = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }
        end = {"type": "message_stop"}
    else:
        path = "/v1/responses"
        body = {"input": "clean", "stream": True}
        delta = {"type": "response.output_text.delta", "item_id": "x", "delta": text}
        end = {"type": "response.completed", "response": {"output": []}}
    raw = _event(str(delta["type"]), delta) + _event(str(end["type"]), end)
    upstream = _Upstream(
        {path: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=raw)}
    )
    if mode == "shadow":
        shield = ss.Shield(
            ss.ShieldConfig.for_mode("shadow", max_input_chars=8),
            extra_detectors=[_MarkerDetector()],
        )
    else:
        shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 200
    if mode == "balanced":
        assert _MARKER.encode() not in response.content
    else:
        assert response.content == raw
    _receipt(request, protocol=protocol, boundary="response", transport="sse")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage"
    ][-1]
    assert event["text_units_scanned"] >= 1
    if mode == "shadow":
        assert event["status"] != "full" and event["budget_exceeded"]


@pytest.mark.parametrize(
    ("event_type", "done_type", "field"),
    [
        ("response.custom_tool_call_input.delta", "response.custom_tool_call_input.done", "input"),
        (
            "response.code_interpreter_call_code.delta",
            "response.code_interpreter_call_code.done",
            "code",
        ),
    ],
)
async def test_plaintext_tool_delta_and_done_are_allowed_without_json_malformed(
    request: pytest.FixtureRequest, event_type: str, done_type: str, field: str
) -> None:
    delta = {"type": event_type, "item_id": "tool", "delta": "print('safe plaintext')"}
    done = {"type": done_type, "item_id": "tool", field: "print('safe plaintext')"}
    completed = {"type": "response.completed", "response": {"output": []}}
    raw = (
        _event(event_type, delta, b"\r\n")
        + _event(done_type, done, b"\n")
        + _event("response.completed", completed, b"\r\n")
    )
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200, headers={"content-type": "text/event-stream"}, content=raw
            )
        }
    )
    shield, _ = _shield()
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean", "stream": True}
        )
    assert response.status_code == 200 and response.content == raw
    _receipt(request, protocol="responses", boundary="response", transport="sse", status="full")


@pytest.mark.parametrize("mode", ["balanced", "shadow"])
async def test_incomplete_tool_json_done_is_nonfull_and_shadow_keeps_exact_bytes(
    request: pytest.FixtureRequest, mode: str
) -> None:
    delta = {"type": "response.function_call_arguments.delta", "item_id": "tool", "delta": '{"x":'}
    done = {"type": "response.function_call_arguments.done", "item_id": "tool"}
    raw = _event(delta["type"], delta) + _event(done["type"], done)
    upstream = _Upstream(
        {
            "/v1/responses": httpx.Response(
                200, headers={"content-type": "text/event-stream"}, content=raw
            )
        }
    )
    shield, _ = _shield(mode)
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(
            "/v1/responses", json={"model": "gpt-synthetic", "input": "clean", "stream": True}
        )
    assert response.status_code == 200
    if mode == "shadow":
        assert response.content == raw
    else:
        assert b"server_error" in response.content
    _receipt(request, protocol="responses", boundary="response", transport="sse")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage"
    ][-1]
    assert event["status"] != "full" and event["malformed_units"] >= 1


@pytest.mark.parametrize(
    ("path", "protocol", "raw"),
    [
        ("/v1/responses", "responses", b'{"input":[{"type":[]}]}'),
        (
            "/v1/messages",
            "anthropic",
            b'event: content_block_delta\ndata: {"type":{},"delta":{}}\n\n',
        ),
    ],
)
async def test_shadow_nonstring_type_discriminator_never_500_and_is_nonfull(
    request: pytest.FixtureRequest, path: str, protocol: str, raw: bytes
) -> None:
    stream = path.endswith("messages")
    headers = (
        {"content-type": "text/event-stream"} if stream else {"content-type": "application/json"}
    )
    upstream = _Upstream({path: httpx.Response(200, headers=headers, content=raw)})
    shield, _ = _shield("shadow")
    body: dict[str, Any] = {"model": "gpt-synthetic", "input": "clean", "stream": stream}
    if protocol == "anthropic":
        body = {"model": "claude-synthetic", "max_tokens": 8, "messages": [], "stream": True}
    async with _client(_app(upstream, shield)) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 200 and response.content == raw
    _receipt(request, protocol=protocol, boundary="response", transport="sse" if stream else "json")
    event = [
        entry
        for entry in getattr(request.node, "_synthetic_coverage_logs", [])
        if entry.get("event") == "shadowshield.proxy.coverage"
    ][-1]
    assert event["status"] != "full"


def test_one_character_fragment_work_is_interval_bounded_and_empty_deltas_are_inert() -> None:
    extractor = StreamProtocolExtractor("responses", scan_interval_chars=256)
    views = 0
    for _ in range(1024):
        result = extractor.consume(
            {"type": "response.function_call_arguments.delta", "item_id": "tool", "delta": "x"}
        )
        views += len(result.texts)
    assert views == 4
    assert extractor._scan_work_chars <= 3 * 1024
    assert extractor.has_pending
    empty = extractor.consume(
        {"type": "response.function_call_arguments.delta", "item_id": "empty", "delta": ""}
    )
    assert empty.texts == []
    assert len(extractor._tool_buffers) == 1
