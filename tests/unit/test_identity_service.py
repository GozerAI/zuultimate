"""Unit tests for IdentityService."""

import pytest

from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.identity.service import IdentityService


@pytest.fixture
def svc(test_db, test_settings):
    return IdentityService(test_db, test_settings)


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


async def test_register_success(svc):
    result = await svc.register("alice@test.com", "alice", "password123")
    assert result["email"] == "alice@test.com"
    assert result["username"] == "alice"
    assert result["is_active"] is True
    assert "id" in result


async def test_register_duplicate_email(svc):
    await svc.register("dup@test.com", "user1", "password123")
    with pytest.raises(ValidationError, match="already in use"):
        await svc.register("dup@test.com", "user2", "password123")


async def test_register_duplicate_username(svc):
    await svc.register("a@test.com", "dupuser", "password123")
    with pytest.raises(ValidationError, match="already in use"):
        await svc.register("b@test.com", "dupuser", "password123")


async def test_register_display_name_defaults_to_username(svc):
    result = await svc.register("no-display@test.com", "nodisplay", "password123")
    assert result["display_name"] == "nodisplay"


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


async def test_login_success(svc):
    await svc.register("login@test.com", "loginuser", "password123")
    result = await svc.login("loginuser", "password123")
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"


async def test_login_wrong_password(svc):
    await svc.register("wp@test.com", "wpuser", "password123")
    with pytest.raises(AuthenticationError):
        await svc.login("wpuser", "wrongpass")


async def test_login_nonexistent_user(svc):
    with pytest.raises(AuthenticationError):
        await svc.login("ghost", "password123")


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


async def test_get_user_success(svc):
    reg = await svc.register("get@test.com", "getuser", "password123")
    result = await svc.get_user(reg["id"])
    assert result["username"] == "getuser"


async def test_get_user_not_found(svc):
    with pytest.raises(NotFoundError):
        await svc.get_user("nonexistent-id")


# ---------------------------------------------------------------------------
# refresh_token
# ---------------------------------------------------------------------------


async def test_refresh_token_success(svc):
    await svc.register("ref@test.com", "refuser", "password123")
    login_result = await svc.login("refuser", "password123")
    refresh = login_result["refresh_token"]
    result = await svc.refresh_token(refresh)
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"


async def test_refresh_token_invalid(svc):
    with pytest.raises(AuthenticationError):
        await svc.refresh_token("garbage.token.here")


async def test_refresh_with_access_token_rejected(svc):
    """Using an access token for refresh should fail (wrong type)."""
    await svc.register("rfa@test.com", "rfauser", "password123")
    login_result = await svc.login("rfauser", "password123")
    with pytest.raises(AuthenticationError, match="Invalid token type"):
        await svc.refresh_token(login_result["access_token"])


async def test_refresh_rotates_session(svc):
    """After refresh, old refresh token should no longer work."""
    await svc.register("rot@test.com", "rotuser", "password123")
    login_result = await svc.login("rotuser", "password123")
    old_refresh = login_result["refresh_token"]
    await svc.refresh_token(old_refresh)
    with pytest.raises(AuthenticationError):
        await svc.refresh_token(old_refresh)


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


async def test_logout_success(svc):
    await svc.register("lo@test.com", "louser", "password123")
    login_result = await svc.login("louser", "password123")
    await svc.logout(login_result["access_token"])
    # Refresh should fail after logout (session deleted)
    with pytest.raises(AuthenticationError):
        await svc.refresh_token(login_result["refresh_token"])


async def test_logout_nonexistent_token(svc):
    """Logout with unknown token should not raise."""
    await svc.logout("nonexistent-token")
