"""Synthetic provider-free checks for detector failures at the proxy boundary."""

from __future__ import annotations

import json

import httpx
import pytest

import shadowshield as ss
from shadowshield.core.types import Direction, Threat
from shadowshield.detectors.base import Detector, ScanContext
from shadowshield.proxy import create_proxy_app

pytest.importorskip("fastapi")

PRIVATE_FAILURE = "synthetic-private-detector-error"
FIRST = "pre"
SECOND = "the-rest-of-the-result"


class BrokenOutputDetector(Detector):
    name = "broken_output_fixture"
    directions = (Direction.OUTPUT,)

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        raise RuntimeError(PRIVATE_FAILURE)


def _chunk(text: str) -> str:
    data = {
        "id": "fixture",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return f"data: {json.dumps(data)}\n\n"


async def _request(mode: str, *, stream: bool):
    """All upstream requests are handled in memory by MockTransport."""
    calls: list[httpx.Request] = []
    response_payload = {
        "id": "fixture",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": SECOND}}],
    }
    stream_body = (_chunk(FIRST) + _chunk(SECOND) + "data: [DONE]\n\n").encode()
    plain_body = json.dumps(response_payload).encode()

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream" if stream else "application/json"},
            content=stream_body if stream else plain_body,
        )

    shield = ss.Shield.for_mode(mode, extra_detectors=[BrokenOutputDetector()])
    app = create_proxy_app(
        shield,
        "http://upstream.test",
        transport=httpx.MockTransport(upstream),
        stream_scan_interval_chars=8,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "mock",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": stream,
            },
        )
    return response, calls, stream_body, plain_body


@pytest.fixture(autouse=True)
def _isolate_ambient_proxy_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHADOWSHIELD_API_KEY", raising=False)


@pytest.mark.asyncio
async def test_nonstream_output_error_enforcement_returns_503_without_body_leak() -> None:
    response, calls, _, _ = await _request("balanced", stream=False)
    assert len(calls) == 1
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "shadowshield_scan_unavailable"
    assert SECOND not in response.text
    assert PRIVATE_FAILURE not in response.text


@pytest.mark.asyncio
async def test_shadow_output_error_preserves_nonstream_and_stream_bytes() -> None:
    plain, plain_calls, _, plain_body = await _request("shadow", stream=False)
    streamed, stream_calls, stream_body, _ = await _request("shadow", stream=True)
    assert len(plain_calls) == len(stream_calls) == 1
    assert plain.status_code == streamed.status_code == 200
    assert plain.content == plain_body
    assert streamed.content == stream_body
    assert PRIVATE_FAILURE not in plain.text and PRIVATE_FAILURE not in streamed.text


@pytest.mark.asyncio
async def test_stream_output_error_halts_but_cannot_recall_previously_forwarded_frames() -> None:
    response, calls, _, _ = await _request("balanced", stream=True)
    assert len(calls) == 1
    assert response.status_code == 200
    assert FIRST in response.text
    assert SECOND not in response.text
    assert "shadowshield_scan_unavailable" in response.text
    assert PRIVATE_FAILURE not in response.text
