"""Unit tests for tenant-scoped JWT claims."""

from zuultimate.common.security import create_jwt, decode_jwt
from zuultimate.identity.service import IdentityService


async def test_token_includes_tenant_id(test_db, test_settings):
    svc = IdentityService(test_db, test_settings)

    # Register a user
    user = await svc.register(
        email="tenant@test.com",
        username="tenantuser",
        password="password123",
    )

    # Manually set tenant_id on the user
    from sqlalchemy import select
    from zuultimate.identity.models import User

    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(User).where(User.id == user["id"])
        )
        db_user = result.scalar_one()
        db_user.tenant_id = "tenant-abc"

    # Login and check token
    result = await svc.login("tenantuser", "password123")
    token = result["access_token"]
    payload = decode_jwt(token, test_settings.secret_key)
    assert payload["tenant_id"] == "tenant-abc"


async def test_token_null_tenant_id(test_db, test_settings):
    svc = IdentityService(test_db, test_settings)

    await svc.register(
        email="notenant@test.com",
        username="notenantuser",
        password="password123",
    )

    result = await svc.login("notenantuser", "password123")
    token = result["access_token"]
    payload = decode_jwt(token, test_settings.secret_key)
    assert payload["tenant_id"] is None


async def test_get_current_user_returns_tenant_id(test_db, test_settings):
    """Verify the auth dependency returns tenant_id."""
    from unittest.mock import MagicMock, AsyncMock
    from zuultimate.common.auth import get_current_user
    from zuultimate.identity.models import User, UserSession
    import hashlib

    svc = IdentityService(test_db, test_settings)
    await svc.register(
        email="authtest@test.com", username="authtest", password="password123"
    )
    login_result = await svc.login("authtest", "password123")
    token = login_result["access_token"]

    # Build a mock request
    request = MagicMock()
    request.app.state.settings = test_settings
    request.app.state.db = test_db

    creds = MagicMock()
    creds.credentials = token

    user_dict = await get_current_user(request, creds)
    assert "tenant_id" in user_dict
    assert user_dict["tenant_id"] is None  # no tenant assigned
