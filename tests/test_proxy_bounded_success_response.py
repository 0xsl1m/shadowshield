"""Bounded response aggregation tests; all upstream calls are in memory."""

from __future__ import annotations

import gzip
import json

import httpx
import pytest

import shadowshield as ss
from shadowshield.proxy import _MAX_INSPECTABLE_BODY_BYTES, create_proxy_app
from shadowshield.proxy_coverage import CoverageReceipt

pytest.importorskip("fastapi")


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self):
        self.closed = True


class BrokenChunks(Chunks):
    async def __aiter__(self):
        self.yielded += 1
        yield b"partial private body"
        raise RuntimeError("synthetic private stream exception")


async def send(
    chunks,
    *,
    mode="balanced",
    enabled=True,
    headers=None,
    upstream_status=200,
    suppress_errors=False,
):
    body_stream = Chunks(chunks)
    requests = []

    def upstream(request):
        requests.append(request)
        return httpx.Response(upstream_status, headers=headers or {}, stream=body_stream)

    app = create_proxy_app(
        ss.Shield.for_mode(mode),
        "http://upstream.test",
        api_keys=["synthetic-gateway"],
        include_environment_keys=False,
        bound_nonstream_success_response=enabled,
        suppress_nonstream_upstream_error_details=suppress_errors,
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-API-Key": "synthetic-gateway", "accept-encoding": "gzip"},
        )
    return response, body_stream, requests


@pytest.mark.asyncio
async def test_bounded_success_forwards_body_but_not_untrusted_headers():
    body = json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode()
    response, stream, requests = await send(
        [body[:5], body[5:]],
        headers={"x-private": "private-identifier", "content-type": "application/json"},
    )
    assert response.status_code == 200 and response.content == body
    assert "x-private" not in response.headers
    assert response.headers["content-type"] == "application/json"
    assert requests[0].headers["accept-encoding"] == "identity"
    assert stream.yielded == 2 and stream.closed


@pytest.mark.asyncio
async def test_over_limit_closes_stream_without_consuming_later_chunks():
    response, stream, _ = await send([b"a" * _MAX_INSPECTABLE_BODY_BYTES, b"x", b"unread"])
    assert response.status_code == 403
    assert "unread" not in response.text
    assert stream.yielded == 2 and stream.closed


@pytest.mark.asyncio
async def test_single_oversized_chunk_is_rejected_without_copying_it_into_accumulator():
    response, stream, _ = await send([b"x" * (_MAX_INSPECTABLE_BODY_BYTES + 1), b"unread"])
    assert response.status_code == 403
    assert stream.yielded == 1 and stream.closed


@pytest.mark.asyncio
async def test_compressed_response_is_rejected_before_application_reads_body():
    response, stream, _ = await send(
        [gzip.compress(b"a" * 2000000)], headers={"content-encoding": "gzip"}
    )
    assert response.status_code == 503
    assert stream.yielded == 0 and stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers"),
    [
        (206, {}),
        (200, {"content-range": "bytes 0-100/10000"}),
        (302, {"location": "https://example.test/"}),
    ],
)
async def test_partial_and_redirect_responses_are_rejected_before_body_read(status, headers):
    response, stream, _ = await send([b"private partial"], upstream_status=status, headers=headers)
    assert response.status_code == 503
    assert b"private partial" not in response.content
    assert stream.yielded == 0 and stream.closed


@pytest.mark.asyncio
async def test_partial_response_coverage_remains_unscanned(monkeypatch):
    receipts = []
    monkeypatch.setattr(
        CoverageReceipt, "emit", lambda self, _log: receipts.append(self.as_event())
    )
    response, _, _ = await send([b"private partial"], upstream_status=206)
    assert response.status_code == 503
    response_receipts = [item for item in receipts if item["phase"] == "response"]
    assert len(response_receipts) == 1
    assert response_receipts[0]["status"] == "unscanned"
    assert response_receipts[0]["reason"] == "unknown_shape"


@pytest.mark.asyncio
async def test_stream_failure_does_not_expose_exception_or_partial_body():
    stream = BrokenChunks([])
    app = create_proxy_app(
        ss.Shield.for_mode("balanced"),
        "http://upstream.test",
        api_keys=["synthetic-gateway"],
        include_environment_keys=False,
        bound_nonstream_success_response=True,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream)),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-API-Key": "synthetic-gateway"},
        )
    assert response.status_code == 503
    assert "partial private" not in response.text and "synthetic private" not in response.text
    assert stream.closed


@pytest.mark.asyncio
async def test_prebuffered_custom_transport_fails_closed():
    app = create_proxy_app(
        ss.Shield.for_mode("balanced"),
        "http://upstream.test",
        api_keys=["synthetic-gateway"],
        include_environment_keys=False,
        bound_nonstream_success_response=True,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"buffered private")),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-API-Key": "synthetic-gateway"},
        )
    assert response.status_code == 503 and "buffered private" not in response.text


@pytest.mark.asyncio
async def test_shadow_forwards_original_body_and_headers_with_option_enabled():
    response, stream, requests = await send(
        [b"original"], mode="shadow", headers={"x-private": "unchanged"}
    )
    assert response.status_code == 200 and response.content == b"original"
    assert response.headers["x-private"] == "unchanged"
    assert requests[0].headers["accept-encoding"] == "gzip"
    assert stream.yielded == 1 and stream.closed


@pytest.mark.asyncio
async def test_disabled_option_preserves_prior_success_headers():
    body = b'{"choices":[{"message":{"content":"hello"}}]}'
    response, stream, _ = await send([body], enabled=False, headers={"x-private": "unchanged"})
    assert response.status_code == 200 and response.content == body
    assert response.headers["x-private"] == "unchanged"
    assert stream.closed


@pytest.mark.asyncio
async def test_error_behavior_unchanged_if_error_withholding_not_enabled():
    response, stream, _ = await send(
        [b"private upstream error"], upstream_status=429, headers={"x-private": "unchanged"}
    )
    assert response.status_code == 429 and response.content == b"private upstream error"
    assert response.headers["x-private"] == "unchanged"
    assert stream.closed


@pytest.mark.asyncio
async def test_combined_option_withholds_error_without_reading_upstream():
    response, stream, _ = await send(
        [b"private upstream error"],
        upstream_status=429,
        headers={"x-private": "sensitive header"},
        suppress_errors=True,
    )
    assert response.status_code == 429 and b"private" not in response.content
    assert "x-private" not in response.headers
    assert stream.yielded == 0 and stream.closed


def test_opt_in_requires_boolean_and_response_scanning():
    for value in (None, 1, "true"):
        with pytest.raises(TypeError):
            create_proxy_app(
                ss.Shield.for_mode("shadow"),
                "http://upstream.test",
                bound_nonstream_success_response=value,
            )
    with pytest.raises(ValueError):
        create_proxy_app(
            ss.Shield.for_mode("balanced"),
            "http://upstream.test",
            scan_response=False,
            bound_nonstream_success_response=True,
        )
