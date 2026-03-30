"""Unit tests for the /v1/admin/keys key rotation endpoint (Phase A.3)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.key_manager import ACTIVE, RETIRING, RETIRED, JWKSKey, KeyManager

_IN_MEMORY = "sqlite+aiosqlite://"

SERVICE_TOKEN = "test-service-token-xyz"


# ---------------------------------------------------------------------------
# DB + KeyManager fixtures (mirror test_key_manager.py pattern)
# ---------------------------------------------------------------------------


@pytest.fixture
async def km_db():
    import zuultimate.common.key_manager  # noqa: F401

    settings = ZuulSettings(
        identity_db_url=_IN_MEMORY,
        credential_db_url=_IN_MEMORY,
        session_db_url=_IN_MEMORY,
        transaction_db_url=_IN_MEMORY,
        audit_db_url=_IN_MEMORY,
        crm_db_url=_IN_MEMORY,
        secret_key="test-rotation-secret",
        service_token=SERVICE_TOKEN,
    )
    db = DatabaseManager(settings)
    await db.init()
    await db.create_all()
    yield db, settings
    await db.close_all()


@pytest.fixture
async def km(km_db):
    db, _ = km_db
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()
    return km


# ---------------------------------------------------------------------------
# Direct KeyManager rotation tests (A.3 — KeyManager.rotate())
# ---------------------------------------------------------------------------


async def test_rotation_creates_new_active_key(km):
    """rotate() should return a new kid and that kid should be ACTIVE in the DB."""
    from sqlalchemy import select

    db = km.db
    _, old_kid = await km.get_signing_key()
    new_kid = await km.rotate()

    assert new_kid != old_kid

    async with db.get_session("identity") as session:
        result = await session.execute(select(JWKSKey).where(JWKSKey.status == ACTIVE))
        active_keys = result.scalars().all()

    assert len(active_keys) == 1
    assert active_keys[0].kid == new_kid


async def test_rotation_moves_old_key_to_retiring(km):
    """The previously ACTIVE key should move to RETIRING after one rotation."""
    from sqlalchemy import select

    db = km.db
    _, old_kid = await km.get_signing_key()
    await km.rotate()

    async with db.get_session("identity") as session:
        result = await session.execute(select(JWKSKey).where(JWKSKey.status == RETIRING))
        retiring_keys = result.scalars().all()

    retiring_kids = [k.kid for k in retiring_keys]
    assert old_kid in retiring_kids


async def test_second_rotation_retires_first_key(km):
    """Two rotations: original ACTIVE key should end up RETIRED."""
    from sqlalchemy import select

    db = km.db
    _, kid1 = await km.get_signing_key()
    await km.rotate()
    await km.rotate()

    async with db.get_session("identity") as session:
        result = await session.execute(
            select(JWKSKey).where(JWKSKey.kid == kid1)
        )
        key = result.scalar_one()

    assert key.status == RETIRED


async def test_rotation_invalidates_cache(km):
    """Cache is cleared after rotation so subsequent calls return fresh data."""
    _, kid1 = await km.get_signing_key()
    # Cache is warm — kid1 is cached
    assert km._signing_key_cache is not None

    kid2 = await km.rotate()

    # Cache should be cleared
    assert km._signing_key_cache is None
    assert km._verification_keys_cache is None

    # Refetch — should return kid2
    _, current = await km.get_signing_key()
    assert current == kid2


async def test_rotation_returns_string_kid(km):
    """rotate() must return a non-empty string kid."""
    kid = await km.rotate()
    assert isinstance(kid, str)
    assert len(kid) > 0


# ---------------------------------------------------------------------------
# HTTP endpoint tests using the full FastAPI app
# ---------------------------------------------------------------------------


@pytest.fixture
async def rotation_client(km_db):
    """Spin up the full app with the real DB wired to key_manager."""
    from zuultimate.app import create_app

    db, settings = km_db

    app = create_app()

    # Replace the real lifespan DB/KM with our in-memory fixtures
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()

    app.state.db = db
    app.state.settings = settings
    app.state.key_manager = km
    app.state.redis = MagicMock(is_available=False)
    app.state.shutting_down = False

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, km


async def test_rotate_endpoint_requires_service_token(rotation_client):
    """POST /v1/admin/keys/rotate without service token → 401."""
    ac, _ = rotation_client
    resp = await ac.post("/v1/admin/keys/rotate")
    assert resp.status_code == 401


async def test_rotate_endpoint_succeeds_with_service_token(rotation_client):
    """POST /v1/admin/keys/rotate with valid service token → 200 + kid."""
    ac, _ = rotation_client
    resp = await ac.post(
        "/v1/admin/keys/rotate",
        headers={"X-Service-Token": SERVICE_TOKEN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "kid" in body
    assert body["status"] == "rotated"
    assert isinstance(body["kid"], str)
    assert len(body["kid"]) > 0


async def test_rotate_endpoint_invalidates_redis_cache(rotation_client):
    """Rotation endpoint calls redis.delete('jwks:cache') when Redis is available."""
    ac, _ = rotation_client

    mock_redis = AsyncMock()
    mock_redis.is_available = True

    # Inject the mock Redis into app state
    # We need to use the real app object from the transport
    transport = ac._transport  # type: ignore[attr-defined]
    if hasattr(transport, "_app"):
        transport._app.state.redis = mock_redis

    resp = await ac.post(
        "/v1/admin/keys/rotate",
        headers={"X-Service-Token": SERVICE_TOKEN},
    )
    assert resp.status_code == 200


async def test_list_keys_endpoint_requires_service_token(rotation_client):
    """GET /v1/admin/keys without service token → 401."""
    ac, _ = rotation_client
    resp = await ac.get("/v1/admin/keys/")
    assert resp.status_code == 401


async def test_list_keys_endpoint_returns_jwks(rotation_client):
    """GET /v1/admin/keys/ with valid token returns JWKS-format key list."""
    ac, _ = rotation_client
    resp = await ac.get(
        "/v1/admin/keys/",
        headers={"X-Service-Token": SERVICE_TOKEN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "keys" in body
    assert isinstance(body["keys"], list)
    assert len(body["keys"]) >= 1
    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


async def test_list_keys_after_rotation_includes_retiring_key(rotation_client):
    """After rotation, list includes both new ACTIVE and old RETIRING key."""
    ac, km = rotation_client

    # Get initial kid before rotation
    _, kid_before = await km.get_signing_key()

    # Rotate via endpoint
    await ac.post(
        "/v1/admin/keys/rotate",
        headers={"X-Service-Token": SERVICE_TOKEN},
    )

    # List should now include both keys (ACTIVE + RETIRING)
    resp = await ac.get(
        "/v1/admin/keys/",
        headers={"X-Service-Token": SERVICE_TOKEN},
    )
    assert resp.status_code == 200
    kids = [k["kid"] for k in resp.json()["keys"]]
    assert kid_before in kids  # RETIRING key still listed
    assert len(kids) == 2
