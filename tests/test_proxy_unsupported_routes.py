"""Provider-free security checks for unmatched gateway routes."""

from __future__ import annotations

import httpx
import pytest

import shadowshield as ss
from shadowshield.proxy import create_proxy_app

pytest.importorskip("fastapi")


@pytest.fixture(autouse=True)
def _isolate_ambient_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHADOWSHIELD_API_KEY", raising=False)


def _app(mode: str, calls: list[httpx.Request], *, metadata: bool = False):
    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200, content=b"synthetic upstream response", headers={"content-type": "text/plain"}
        )

    return create_proxy_app(
        ss.Shield.for_mode(mode),
        "http://upstream.test",
        api_keys=["fixture-gateway-key"],
        include_environment_keys=False,
        allow_unscanned_model_metadata=metadata,
        transport=httpx.MockTransport(upstream),
    )


@pytest.mark.parametrize("mode", ["balanced", "strict", "permissive"])
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v2/synthetic-generate?secret=synthetic-private"),
        ("POST", "/v1/embeddings"),
        ("GET", "/v1/responses/example"),
        ("GET", "/v1/models"),
        ("DELETE", "/v1/files/example"),
    ],
)
async def test_enforcing_unknown_routes_fail_closed_before_upstream(
    mode: str, method: str, path: str
) -> None:
    calls: list[httpx.Request] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(mode, calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.request(
            method,
            path,
            content=b"synthetic-private-content",
            headers={"X-API-Key": "fixture-gateway-key"},
        )
        health = await client.get("/health")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "shadowshield_unsupported_route"
    assert "synthetic-private" not in response.text
    assert calls == []
    assert health.json()["requests_total"] == 0


async def test_shadow_forwards_unknown_path_body_and_response_unchanged() -> None:
    calls: list[httpx.Request] = []
    body = b"synthetic\x00payload\xff"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("shadow", calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.post(
            "/v2/synthetic-generate?variant=a",
            content=body,
            headers={"X-API-Key": "fixture-gateway-key"},
        )
    assert response.status_code == 200
    assert response.content == b"synthetic upstream response"
    assert len(calls) == 1
    assert calls[0].url.path == "/v2/synthetic-generate"
    assert calls[0].url.query == b"variant=a"
    assert calls[0].content == body


async def test_metadata_opt_in_is_narrow_and_bodyless() -> None:
    calls: list[httpx.Request] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls, metadata=True)),
        base_url="http://proxy.test",
    ) as client:
        headers = {"X-API-Key": "fixture-gateway-key"}
        listed = await client.get("/v1/models?limit=3", headers=headers)
        listed_head = await client.head("/v1/models/", headers=headers)
        with_body = await client.request("GET", "/v1/models", content=b"prompt", headers=headers)
        wrong_method = await client.post("/v1/models", headers=headers)
        extension = await client.get("/v1/models/example", headers=headers)
    assert listed.status_code == listed_head.status_code == 200
    assert [with_body.status_code, wrong_method.status_code, extension.status_code] == [503] * 3
    assert len(calls) == 2 and calls[0].url.query == b"limit=3"


async def test_metadata_list_is_denied_by_default_even_without_body() -> None:
    calls: list[httpx.Request] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.get("/v1/models", headers={"X-API-Key": "fixture-gateway-key"})
    assert response.status_code == 503
    assert calls == []


async def test_authentication_still_precedes_unsupported_route_guard() -> None:
    calls: list[httpx.Request] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app("balanced", calls)), base_url="http://proxy.test"
    ) as client:
        response = await client.post("/v2/synthetic-generate", content=b"attack")
    assert response.status_code == 401
    assert calls == []


@pytest.mark.parametrize("option", ["false", 1, None])
def test_metadata_opt_in_requires_explicit_boolean(option: object) -> None:
    with pytest.raises(TypeError, match="must be a boolean"):
        create_proxy_app(
            ss.Shield.for_mode("balanced"),
            "http://upstream.test",
            allow_unscanned_model_metadata=option,  # type: ignore[arg-type]
        )
