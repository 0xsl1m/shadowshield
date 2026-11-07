"""Provider-free checks for experimental incomplete-extraction rejection."""

import json

import httpx
import pytest

import shadowshield as ss
from shadowshield.proxy import create_proxy_app

pytest.importorskip("fastapi")
pytestmark = pytest.mark.asyncio


def _app(mode, calls, *, output=None, enabled=True):
    def upstream(request):
        calls.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "x-test": "preserved"},
            content=json.dumps(
                output
                if output is not None
                else {"output": [{"type": "output_text", "text": "hello"}]}
            ).encode(),
        )

    return create_proxy_app(
        ss.Shield.for_mode(mode),
        "http://upstream.test",
        api_keys=["gateway-test"],
        include_environment_keys=False,
        require_nonstream_bidirectional=True,
        reject_incomplete_extraction=enabled,
        transport=httpx.MockTransport(upstream),
    )


@pytest.mark.parametrize(
    "block",
    [
        {"type": "input_image", "image_url": "https://example.test/image"},
        {"type": "file_reference", "file_id": "synthetic-file"},
        {"type": "reasoning", "encrypted_content": "synthetic-opaque"},
    ],
)
async def test_enforcing_rejects_opaque_media_and_reference_requests(block):
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/responses", json={"input": [block]}, headers={"x-api-key": "gateway-test"}
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "shadowshield_scan_unavailable"
    assert not calls


@pytest.mark.parametrize(
    "block",
    [
        {"type": "output_image", "image_url": "https://example.test/image"},
        {"type": "item_reference", "id": "synthetic-item"},
        {"type": "reasoning", "encrypted_content": "synthetic-opaque"},
    ],
)
async def test_enforcing_withholds_incomplete_response(block):
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls, output={"output": [block]})),
        base_url="http://proxy.test",
    ) as client:
        response = await client.post(
            "/v1/responses", json={"input": "hello"}, headers={"x-api-key": "gateway-test"}
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "shadowshield_scan_unavailable"
    assert "synthetic" not in response.text
    assert len(calls) == 1


async def test_shadow_preserves_incomplete_request_and_response_bytes():
    calls = []
    output = {"output": [{"type": "reasoning", "encrypted_content": "synthetic-opaque"}]}
    body = b'{"input":[{"type":"input_image","image_url":"https://example.test/image"}]}'
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("shadow", calls, output=output)),
        base_url="http://proxy.test",
    ) as client:
        response = await client.post(
            "/v1/responses", content=body, headers={"x-api-key": "gateway-test"}
        )
    assert calls[0].content == body
    assert response.status_code == 200
    assert response.content == json.dumps(output).encode()
    assert response.headers["x-test"] == "preserved"


async def test_complete_text_remains_accepted():
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v1/responses", json={"input": "hello"}, headers={"x-api-key": "gateway-test"}
        )
    assert response.status_code == 200
    assert len(calls) == 1


@pytest.mark.parametrize("mode, expected", [("balanced", 403), ("shadow", 200)])
async def test_empty_json_response_is_not_treated_as_a_complete_response(mode, expected):
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(mode, calls, output={}, enabled=False)),
        base_url="http://proxy.test",
    ) as client:
        response = await client.post(
            "/v1/responses", json={"input": "hello"}, headers={"x-api-key": "gateway-test"}
        )
    assert len(calls) == 1
    assert response.status_code == expected
    if mode == "shadow":
        assert response.content == b"{}"


async def test_option_disabled_retains_existing_opaque_compatibility():
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls, enabled=False)),
        base_url="http://proxy.test",
    ) as client:
        response = await client.post(
            "/v1/responses",
            json={"input": [{"type": "reasoning", "encrypted_content": "synthetic"}]},
            headers={"x-api-key": "gateway-test"},
        )
    assert response.status_code == 200
    assert len(calls) == 1


async def test_option_requires_bidirectional_nonstream_and_boolean():
    shield = ss.Shield.for_mode("balanced")
    with pytest.raises(ValueError, match="requires non-stream bidirectional"):
        create_proxy_app(shield, "http://upstream.test", reject_incomplete_extraction=True)
    with pytest.raises(TypeError, match="must be a boolean"):
        create_proxy_app(
            shield,
            "http://upstream.test",
            require_nonstream_bidirectional=True,
            reject_incomplete_extraction=1,
        )
