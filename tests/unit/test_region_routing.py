"""Unit tests for RegionRoutingMiddleware (Phase A.1)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from zuultimate.common.middleware import RegionRoutingMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(current_region: str = "us", tenant_home_region: str | None = None):
    """Build a minimal FastAPI app wired with RegionRoutingMiddleware.

    *tenant_home_region* controls what the mock DB returns when queried.
    """
    app = FastAPI()
    app.add_middleware(RegionRoutingMiddleware, region=current_region)

    @app.get("/v1/protected")
    async def protected():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    async def jwks():
        return {"keys": []}

    @app.get("/metrics")
    async def metrics():
        return {}

    @app.get("/v1/identity/auth/validate")
    async def auth_validate():
        return {"active": True}

    # Attach a mock DB that returns the configured tenant home_region
    mock_db = MagicMock()
    mock_session = AsyncMock()

    if tenant_home_region is not None:
        mock_row = MagicMock()
        mock_row.__getitem__ = MagicMock(side_effect=lambda i: tenant_home_region if i == 0 else None)
        mock_result = MagicMock()
        mock_result.first.return_value = (tenant_home_region,)
        mock_session.execute = AsyncMock(return_value=mock_result)
    else:
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_db.get_session.return_value = mock_session

    app.state.db = mock_db
    return app


def _make_jwt_with_tenant(tenant_id: str) -> str:
    """Create a real (HS256) JWT carrying a tenant_id claim for middleware inspection."""
    import jwt

    return jwt.encode(
        {"sub": "user123", "type": "access", "tenant_id": tenant_id},
        "test-secret",
        algorithm="HS256",
    )


def _make_jwt_no_tenant() -> str:
    """Create a real JWT with no tenant_id claim."""
    import jwt

    return jwt.encode(
        {"sub": "user123", "type": "access"},
        "test-secret",
        algorithm="HS256",
    )


# ---------------------------------------------------------------------------
# Exempt paths — always pass through regardless of token / region
# ---------------------------------------------------------------------------


async def test_health_path_exempt():
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/health")
    assert resp.status_code == 200


async def test_jwks_path_exempt():
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/.well-known/jwks.json")
    assert resp.status_code == 200


async def test_metrics_path_exempt():
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/metrics")
    assert resp.status_code == 200


async def test_auth_path_exempt():
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/v1/identity/auth/validate")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# No auth header — passes through
# ---------------------------------------------------------------------------


async def test_no_auth_header_passes_through():
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/v1/protected")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# API key auth (gzr_ prefix) — no region check
# ---------------------------------------------------------------------------


async def test_api_key_auth_passes_through():
    """API keys (gzr_ prefix) bypass region routing entirely."""
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": "Bearer gzr_some-api-key-value"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# JWT with tenant in matching region — passes through
# ---------------------------------------------------------------------------


async def test_matching_region_passes_through():
    """When tenant home_region == current region, no redirect is issued."""
    tenant_id = "tenant-us-001"
    token = _make_jwt_with_tenant(tenant_id)
    app = _make_app(current_region="us", tenant_home_region="us")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# JWT with tenant in a different region — 307 redirect
# ---------------------------------------------------------------------------


async def test_region_mismatch_returns_307():
    """Tenant homed in EU triggers a 307 redirect from a US node."""
    tenant_id = "tenant-eu-001"
    token = _make_jwt_with_tenant(tenant_id)
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 307
    assert "zuultimate-eu.gozerai.com" in resp.headers["location"]
    assert "/v1/protected" in resp.headers["location"]


async def test_region_mismatch_redirect_contains_path():
    """Redirect Location preserves the original request path."""
    tenant_id = "tenant-ap-001"
    token = _make_jwt_with_tenant(tenant_id)
    app = _make_app(current_region="us", tenant_home_region="ap")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 307
    assert resp.headers["location"] == "https://zuultimate-ap.gozerai.com/v1/protected"


# ---------------------------------------------------------------------------
# JWT with no tenant_id claim — passes through (no tenant to look up)
# ---------------------------------------------------------------------------


async def test_jwt_without_tenant_id_passes_through():
    """JWTs carrying no tenant_id have no home region to check — pass through."""
    token = _make_jwt_no_tenant()
    app = _make_app(current_region="us", tenant_home_region=None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Malformed / non-JWT Bearer token — swallowed, passes through
# ---------------------------------------------------------------------------


async def test_malformed_bearer_token_passes_through():
    """Garbage Bearer tokens are silently ignored and the request passes through."""
    app = _make_app(current_region="us", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": "Bearer not-a-real-jwt-value"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Tenant not found in DB — passes through gracefully
# ---------------------------------------------------------------------------


async def test_unknown_tenant_passes_through():
    """If tenant is not in the DB, the guard falls through without redirecting."""
    tenant_id = "tenant-unknown"
    token = _make_jwt_with_tenant(tenant_id)
    # tenant_home_region=None → DB returns no row
    app = _make_app(current_region="us", tenant_home_region=None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# RegionRoutingMiddleware initialised with non-default region
# ---------------------------------------------------------------------------


async def test_eu_node_passes_eu_tenant():
    """An EU-configured node does not redirect an EU tenant."""
    tenant_id = "tenant-eu-x"
    token = _make_jwt_with_tenant(tenant_id)
    app = _make_app(current_region="eu", tenant_home_region="eu")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


async def test_eu_node_redirects_us_tenant():
    """An EU-configured node redirects a US-homed tenant back to the US region."""
    tenant_id = "tenant-us-x"
    token = _make_jwt_with_tenant(tenant_id)
    app = _make_app(current_region="eu", tenant_home_region="us")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
    ) as ac:
        resp = await ac.get(
            "/v1/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 307
    assert "zuultimate-us.gozerai.com" in resp.headers["location"]
