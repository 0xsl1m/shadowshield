"""The proxy's catch-all must have the same access boundary as guarded routes."""

from __future__ import annotations

import asyncio

import httpx
import pytest

import shadowshield as ss
import shadowshield.proxy as proxy
from shadowshield._security import ConcurrencyLimitMiddleware

pytest.importorskip("fastapi")


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHADOWSHIELD_API_KEY", raising=False)


@pytest.mark.asyncio
async def test_only_get_health_is_public_for_any_proxy_path() -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="upstream")

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        assert (await client.get("/health")).status_code == 200
        for method, path in (
            ("POST", "/v2/generate"),
            ("GET", "/v2/models"),
            ("OPTIONS", "/v2/generate"),
            ("POST", "/health"),
            ("GET", "/health/"),
            ("GET", "/"),
        ):
            response = await client.request(method, path)
            assert response.status_code == 401, (method, path)
        assert calls == []
        assert (await client.get("/health")).json()["requests_total"] == 0
        response = await client.post("/v2/generate", headers={"x-api-key": "gateway-key"})
        assert response.status_code == 200
        assert len(calls) == 1
        assert "x-api-key" not in calls[0].headers


@pytest.mark.asyncio
async def test_non_v1_paths_share_capacity_while_health_stays_responsive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class OneAtATime(ConcurrencyLimitMiddleware):
        def __init__(self, app, **kwargs):
            super().__init__(app, **kwargs, max_concurrency=1)

    async def upstream(request: httpx.Request) -> httpx.Response:
        entered.set()
        await release.wait()
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(proxy, "ConcurrencyLimitMiddleware", OneAtATime)
    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        first = asyncio.create_task(
            client.post("/v2/generate", headers={"x-api-key": "gateway-key"})
        )
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            second = await client.get("/v3/models", headers={"x-api-key": "gateway-key"})
            health = await client.get("/health")
            assert second.status_code == 503
            assert health.status_code == 200
        finally:
            release.set()
            assert (await first).status_code == 200


@pytest.mark.asyncio
async def test_cors_preflight_wrapper_stays_outside_proxy_auth() -> None:
    from starlette.middleware.cors import CORSMiddleware

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
    )
    cors = CORSMiddleware(
        app, allow_origins=["https://app.example"], allow_methods=["POST"], allow_headers=["*"]
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=cors), base_url="http://gateway.test"
    ) as client:
        preflight = await client.options(
            "/v2/generate",
            headers={"origin": "https://app.example", "access-control-request-method": "POST"},
        )
        assert preflight.status_code == 200
        assert (await client.options("/v2/generate")).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "stream"),
    [("/v1/chat/completions", False), ("/v1/chat/completions", True), ("/v2/generate", False)],
)
async def test_gateway_bearer_is_never_sent_upstream(path: str, stream: bool) -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"choices": []})

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        payload = {"model": "mock", "messages": [{"role": "user", "content": "hello"}]}
        if stream:
            payload["stream"] = True
        for headers in (
            {"authorization": "Bearer gateway-key"},
            {"x-api-key": "gateway-key", "authorization": "bearer gateway-key"},
        ):
            response = await client.post(path, headers=headers, json=payload)
            assert response.status_code == 200
            assert "authorization" not in calls[-1].headers
            assert "x-api-key" not in calls[-1].headers


@pytest.mark.asyncio
async def test_distinct_provider_bearer_is_preserved_with_gateway_key() -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"choices": []})

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        headers = {"x-api-key": "gateway-key", "authorization": "Bearer provider-key"}
        for path in ("/v1/chat/completions", "/v2/generate"):
            response = await client.post(path, headers=headers, json={"model": "mock"})
            assert response.status_code == 200
            assert calls[-1].headers["authorization"] == "Bearer provider-key"
            assert "x-api-key" not in calls[-1].headers

        # A provider bearer without a gateway credential is not gateway auth.
        denied = await client.post("/v2/generate", headers={"authorization": "Bearer provider-key"})
        assert denied.status_code == 401
        assert len(calls) == 2

        # X-API-Key is the gateway credential when both headers are present;
        # a provider key there must not be accepted via a valid gateway bearer.
        denied = await client.post(
            "/v2/generate",
            headers={"x-api-key": "provider-key", "authorization": "Bearer gateway-key"},
        )
        assert denied.status_code == 401
        assert len(calls) == 2


@pytest.mark.asyncio
async def test_duplicate_authorization_headers_cannot_forward_gateway_key() -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"choices": []})

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.post(
            "/v2/generate",
            headers=[
                ("x-api-key", "gateway-key"),
                ("authorization", "Bearer provider-key"),
                ("authorization", "Bearer gateway-key"),
            ],
        )
        assert response.status_code == 200
        assert calls[-1].headers["authorization"] == "Bearer provider-key"
        assert "gateway-key" not in str(calls[-1].headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [
        "Bearer gateway-key, Bearer provider-key",
        "Bearer provider-key, Bearer gateway-key",
        "Bearer\tgateway-key, Bearer provider-key",
        "Bearer provider-key, Bearer\tgateway-key",
        "Bearer\tgateway-key",
    ],
)
async def test_combined_or_noncanonical_gateway_bearer_is_not_forwarded(
    authorization: str,
) -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.post(
            "/v2/generate", headers={"x-api-key": "gateway-key", "authorization": authorization}
        )
        assert response.status_code == 200
        assert "authorization" not in calls[-1].headers


@pytest.mark.asyncio
async def test_provider_bearer_is_preserved_when_gateway_has_no_configured_keys() -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.get("/v2/models", headers={"authorization": "Bearer provider-key"})
        assert response.status_code == 200
        assert calls[-1].headers["authorization"] == "Bearer provider-key"


@pytest.mark.asyncio
async def test_same_gateway_and_provider_bearer_fails_upstream_without_leaking_key() -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401 if "authorization" not in request.headers else 200)

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=["gateway-key"],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.get(
            "/v2/models",
            headers={"x-api-key": "gateway-key", "authorization": "Bearer gateway-key"},
        )
        assert response.status_code == 401
        assert len(calls) == 1
        assert "authorization" not in calls[0].headers


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["gateway-key ", " gateway-key", " gateway-key "])
async def test_explicit_gateway_key_with_surrounding_whitespace_is_not_forwarded(key: str) -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    app = proxy.create_proxy_app(
        ss.Shield.for_mode("shadow"),
        "http://upstream.test",
        api_keys=[key],
        transport=httpx.MockTransport(upstream),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.get(
            "/v2/models", headers={"x-api-key": key, "authorization": "Bearer gateway-key "}
        )
        assert response.status_code == 200
        assert len(calls) == 1
        assert "authorization" not in calls[0].headers
