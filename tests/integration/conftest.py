"""Shared fixtures for integration tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.redis import RedisManager

_IN_MEMORY = "sqlite+aiosqlite://"


@pytest.fixture
async def integration_client():
    """Create a fresh app with in-memory DB for integration tests."""
    settings = ZuulSettings(
        identity_db_url=_IN_MEMORY,
        credential_db_url=_IN_MEMORY,
        session_db_url=_IN_MEMORY,
        transaction_db_url=_IN_MEMORY,
        audit_db_url=_IN_MEMORY,
        crm_db_url=_IN_MEMORY,
        secret_key="test-secret-key",
    )

    from zuultimate.app import create_app

    app = create_app()

    import zuultimate.identity.models  # noqa: F401
    import zuultimate.access.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.pos.models  # noqa: F401
    import zuultimate.crm.models  # noqa: F401
    import zuultimate.backup_resilience.models  # noqa: F401
    import zuultimate.ai_security.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401
    import zuultimate.common.idempotency  # noqa: F401

    db = DatabaseManager(settings)
    await db.init()
    await db.create_all()

    redis = RedisManager()
    # Don't connect to real Redis in tests -- use in-memory fallback
    redis._available = False

    app.state.db = db
    app.state.settings = settings
    app.state.redis = redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await db.close_all()


async def get_auth_headers(client, username="testuser", password="password123"):
    """Register a user and return Authorization headers."""
    await client.post(
        "/v1/identity/register",
        json={
            "email": f"{username}@test.com",
            "username": username,
            "password": password,
        },
    )
    resp = await client.post(
        "/v1/identity/login",
        json={"username": username, "password": password},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
