"""Shared test fixtures for Zuultimate."""

import pytest
from unittest.mock import patch
from httpx import ASGITransport, AsyncClient

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager


# =============================================================================
# License Gate — allow all features during tests
# =============================================================================


@pytest.fixture(autouse=True)
def _unlock_license_gate():
    """Patch the module-level license_gate singleton so all features are allowed in tests."""
    with patch("zuultimate.common.licensing.license_gate.check_feature", return_value=True):
        yield


@pytest.fixture(autouse=True)
def _skip_pwned_check():
    """Disable HIBP breach lookups during tests to avoid external network calls."""
    with patch(
        "zuultimate.identity.risk.pwned.PwnedPasswordChecker.check",
        return_value=False,
    ):
        yield

_IN_MEMORY = "sqlite+aiosqlite://"


@pytest.fixture
def test_settings():
    return ZuulSettings(
        identity_db_url=_IN_MEMORY,
        credential_db_url=_IN_MEMORY,
        session_db_url=_IN_MEMORY,
        transaction_db_url=_IN_MEMORY,
        audit_db_url=_IN_MEMORY,
        crm_db_url=_IN_MEMORY,
        secret_key="test-secret-key",
    )


@pytest.fixture
async def test_db(test_settings):
    import zuultimate.identity.models  # noqa: F401
    import zuultimate.identity.phase2_models  # noqa: F401
    import zuultimate.access.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.pos.models  # noqa: F401
    import zuultimate.crm.models  # noqa: F401
    import zuultimate.backup_resilience.models  # noqa: F401
    import zuultimate.ai_security.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401
    import zuultimate.common.idempotency  # noqa: F401
    import zuultimate.identity.consent.models  # noqa: F401
    import zuultimate.identity.dsar.models  # noqa: F401
    import zuultimate.common.key_manager  # noqa: F401
    import zuultimate.vault.blind_pass  # noqa: F401
    import zuultimate.vault.cross_service  # noqa: F401
    import zuultimate.identity.workforce.models  # noqa: F401

    db = DatabaseManager(test_settings)
    await db.init()
    await db.create_all()
    yield db
    await db.close_all()


@pytest.fixture
async def key_manager(test_db):
    """Bootstrap a KeyManager with an ACTIVE RSA key for tests."""
    from zuultimate.common.key_manager import KeyManager

    km = KeyManager(test_db, region="us")
    await km.ensure_key_exists()
    return km


@pytest.fixture
def app():
    from zuultimate.app import create_app
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def authenticate(client, username="testuser", password="password123"):
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
