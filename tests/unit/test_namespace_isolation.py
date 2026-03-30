"""Tests for NamespaceMiddleware — namespace isolation between workforce/consumer."""

import pytest
import jwt as pyjwt
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from httpx import ASGITransport, AsyncClient

from zuultimate.common.middleware import NamespaceMiddleware


def _make_token(namespace: str = "consumer", **extra) -> str:
    """Create an unsigned JWT with the given namespace claim."""
    payload = {"sub": "user-1", "namespace": namespace, **extra}
    return pyjwt.encode(payload, "nosecret", algorithm="HS256")


async def _ok_handler(request):
    return JSONResponse({"ok": True})


def _build_app():
    """Build a minimal Starlette app with NamespaceMiddleware."""
    app = Starlette(
        routes=[
            Route("/v1/workforce/me", _ok_handler),
            Route("/v1/workforce/sso/initiate", _ok_handler, methods=["POST"]),
            Route("/v1/tenants", _ok_handler),
            Route("/v1/identity/auth/login", _ok_handler, methods=["POST"]),
            Route("/v1/admin/pops", _ok_handler),
            Route("/health", _ok_handler),
            Route("/metrics", _ok_handler),
            Route("/.well-known/jwks.json", _ok_handler),
        ],
    )
    app.add_middleware(NamespaceMiddleware)
    return app


@pytest.fixture
async def ns_client():
    app = _build_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_workforce_route_with_workforce_ns(ns_client):
    token = _make_token("workforce")
    resp = await ns_client.get(
        "/v1/workforce/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_workforce_route_with_consumer_ns_denied(ns_client):
    token = _make_token("consumer")
    resp = await ns_client.get(
        "/v1/workforce/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
    assert "Workforce namespace required" in resp.text


@pytest.mark.asyncio
async def test_consumer_route_with_consumer_ns(ns_client):
    token = _make_token("consumer")
    resp = await ns_client.get(
        "/v1/tenants", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_consumer_route_with_workforce_ns_denied(ns_client):
    token = _make_token("workforce")
    resp = await ns_client.get(
        "/v1/tenants", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
    assert "Consumer namespace required" in resp.text


@pytest.mark.asyncio
async def test_health_exempt(ns_client):
    resp = await ns_client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_metrics_exempt(ns_client):
    resp = await ns_client.get("/metrics")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_well_known_exempt(ns_client):
    resp = await ns_client.get("/.well-known/jwks.json")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_auth_exempt(ns_client):
    resp = await ns_client.post("/v1/identity/auth/login")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_route_passes_through(ns_client):
    """Admin routes are neither workforce nor consumer — pass through."""
    token = _make_token("workforce")
    resp = await ns_client.get(
        "/v1/admin/pops", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_no_auth_header_passes_through(ns_client):
    """Requests without auth header pass through (let auth middleware handle)."""
    resp = await ns_client.get("/v1/workforce/me")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_key_passes_through(ns_client):
    """API key tokens (gzr_ prefix) pass through without namespace check."""
    resp = await ns_client.get(
        "/v1/tenants", headers={"Authorization": "Bearer gzr_test123"}
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_default_namespace_is_consumer(ns_client):
    """Token without explicit namespace defaults to consumer."""
    payload = {"sub": "user-1"}
    token = pyjwt.encode(payload, "nosecret", algorithm="HS256")
    resp = await ns_client.get(
        "/v1/tenants", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
