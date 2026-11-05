"""Provider-free verification of optional non-stream error-body withholding."""

from __future__ import annotations

import httpx
import pytest

import shadowshield as ss
from shadowshield.proxy import create_proxy_app

pytest.importorskip("fastapi")

PRIVATE = "synthetic private upstream content"


class ErrorStream(httpx.AsyncByteStream):
    def __init__(self, *, unreadable: bool = False) -> None:
        self.read = False
        self.closed = False
        self.unreadable = unreadable

    async def __aiter__(self):
        self.read = True
        if self.unreadable:
            raise AssertionError("the proxy must not read the upstream error body")
        yield PRIVATE.encode()

    async def aclose(self) -> None:
        self.closed = True


async def exchange(mode: str, path: str, *, enabled: bool, status: int, unreadable: bool = False):
    upstream_stream = ErrorStream(unreadable=unreadable)

    def upstream(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"content-type": "application/json", "x-private": PRIVATE},
            stream=upstream_stream,
        )

    app = create_proxy_app(
        ss.Shield.for_mode(mode),
        "http://upstream.test",
        api_keys=["synthetic-key"],
        include_environment_keys=False,
        suppress_nonstream_upstream_error_details=enabled,
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        payload = (
            {"input": "Hi"}
            if path == "/v1/responses"
            else {"messages": [{"role": "user", "content": "Hi"}]}
        )
        response = await client.post(path, json=payload, headers={"X-API-Key": "synthetic-key"})
    return response, upstream_stream


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/messages", "/v1/responses"])
@pytest.mark.parametrize("status", [400, 429, 500])
async def test_opt_in_withholds_body_without_reading_or_forwarding_headers(path, status):
    response, stream = await exchange(
        "balanced", path, enabled=True, status=status, unreadable=True
    )
    assert response.status_code == status
    assert PRIVATE not in response.text
    assert "x-private" not in response.headers
    assert not stream.read and stream.closed
    assert response.json()["error"]["message"] == "Upstream error details withheld by ShadowShield"


@pytest.mark.asyncio
async def test_shadow_preserves_bytes_and_headers_even_when_opted_in():
    response, stream = await exchange("shadow", "/v1/chat/completions", enabled=True, status=429)
    assert response.status_code == 429
    assert response.content == PRIVATE.encode()
    assert response.headers["x-private"] == PRIVATE
    assert stream.read and stream.closed


@pytest.mark.asyncio
async def test_legacy_enforcing_behavior_unchanged_when_opt_out():
    response, stream = await exchange("balanced", "/v1/chat/completions", enabled=False, status=400)
    assert response.content == PRIVATE.encode()
    assert response.headers["x-private"] == PRIVATE
    assert stream.read and stream.closed


@pytest.mark.asyncio
async def test_opt_in_leaves_successful_response_inspection_unchanged():
    payload = b'{"choices":[{"message":{"content":"hello"}}]}'
    app = create_proxy_app(
        ss.Shield.for_mode("balanced"),
        "http://upstream.test",
        api_keys=["synthetic-key"],
        include_environment_keys=False,
        suppress_nonstream_upstream_error_details=True,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload)),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-API-Key": "synthetic-key"},
        )
    assert response.status_code == 200 and response.content == payload


@pytest.mark.asyncio
async def test_opt_in_does_not_claim_streaming_error_protection():
    payload = PRIVATE.encode()
    app = create_proxy_app(
        ss.Shield.for_mode("balanced"),
        "http://upstream.test",
        api_keys=["synthetic-key"],
        include_environment_keys=False,
        suppress_nonstream_upstream_error_details=True,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                429, headers={"content-type": "text/event-stream"}, content=payload
            )
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}], "stream": True},
            headers={"X-API-Key": "synthetic-key"},
        )
    assert response.status_code == 429 and response.content == payload


def test_opt_in_requires_real_boolean():
    with pytest.raises(TypeError):
        create_proxy_app(
            ss.Shield.for_mode("shadow"),
            "http://upstream.test",
            suppress_nonstream_upstream_error_details=1,
        )
