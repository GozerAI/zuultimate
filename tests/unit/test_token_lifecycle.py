"""Tests for Phase 1.2 -- token lifecycle hardening."""

from __future__ import annotations

import hashlib
import time

import jwt as pyjwt
import pytest

from zuultimate.common.exceptions import AuthenticationError
from zuultimate.common.security import _AUDIENCE, _ISSUER, create_jwt, decode_jwt
from zuultimate.identity.service import IdentityService

SECRET = "test-secret-key"


# ---------------------------------------------------------------------------
# JWT iss / aud claims
# ---------------------------------------------------------------------------


def test_jwt_contains_iss_and_aud():
    """Verify create_jwt embeds iss and aud claims."""
    token = create_jwt({"sub": "u1"}, SECRET)
    payload = decode_jwt(token, SECRET)
    assert payload["iss"] == "zuultimate"
    assert payload["aud"] == "zuultimate-api"


def test_decode_jwt_validates_audience():
    """Reject tokens with a wrong audience claim."""
    payload = {
        "sub": "u1",
        "iss": _ISSUER,
        "aud": "wrong-audience",
    }
    token = pyjwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(pyjwt.InvalidAudienceError):
        decode_jwt(token, SECRET, verify_exp=False)


def test_decode_jwt_validates_issuer():
    """Reject tokens with a wrong issuer claim."""
    payload = {
        "sub": "u1",
        "iss": "evil-issuer",
        "aud": _AUDIENCE,
    }
    token = pyjwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(pyjwt.InvalidIssuerError):
        decode_jwt(token, SECRET, verify_exp=False)


def test_expired_token_rejected():
    """Expired tokens raise ExpiredSignatureError."""
    token = create_jwt({"sub": "u1"}, SECRET, expires_minutes=0)
    time.sleep(1)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_jwt(token, SECRET)


# ---------------------------------------------------------------------------
# Refresh token rotation with reuse detection
# ---------------------------------------------------------------------------


@pytest.fixture
def svc(test_db, test_settings):
    return IdentityService(test_db, test_settings)


async def _register_and_login(svc: IdentityService, suffix: str = "") -> dict:
    """Register a user and log in, returning the login result."""
    username = f"tokenuser{suffix}"
    await svc.register(f"{username}@test.com", username, "password123")
    return await svc.login(username, "password123")


async def test_refresh_token_rotation(svc):
    """Refresh returns new tokens and marks the old session as consumed."""
    login_result = await _register_and_login(svc)
    old_refresh = login_result["refresh_token"]

    new_result = await svc.refresh_token(old_refresh)
    assert "access_token" in new_result
    assert "refresh_token" in new_result
    assert new_result["refresh_token"] != old_refresh

    # The old refresh token should now be consumed; using it again triggers reuse detection
    with pytest.raises(AuthenticationError, match="reuse detected"):
        await svc.refresh_token(old_refresh)


async def test_refresh_token_reuse_invalidates_family(svc):
    """Reusing a consumed refresh token deletes all sessions in the family."""
    login_result = await _register_and_login(svc, suffix="reuse")
    old_refresh = login_result["refresh_token"]

    # First rotation -- should succeed
    new_result = await svc.refresh_token(old_refresh)
    new_refresh = new_result["refresh_token"]

    # Reuse the old token -- should kill the whole family
    with pytest.raises(AuthenticationError, match="reuse detected"):
        await svc.refresh_token(old_refresh)

    # The new refresh token should also be invalid now (family wiped)
    with pytest.raises(AuthenticationError, match="Session not found or revoked"):
        await svc.refresh_token(new_refresh)


# ---------------------------------------------------------------------------
# Token introspection
# ---------------------------------------------------------------------------


async def test_introspect_valid_token(svc):
    """Introspecting a valid access token returns active=True with claims."""
    login_result = await _register_and_login(svc, suffix="intro")
    result = await svc.introspect_token(login_result["access_token"])

    assert result["active"] is True
    assert result["sub"] is not None
    assert result["username"] == "tokenuserintro"
    assert result["token_type"] == "access"
    assert result["iss"] == "zuultimate"
    assert result["aud"] == "zuultimate-api"
    assert result["jti"] is not None
    assert result["exp"] is not None
    assert result["iat"] is not None


async def test_introspect_expired_token(svc):
    """Introspecting an expired token returns active=False."""
    # Create a token that expires immediately
    token = create_jwt(
        {"sub": "u1", "type": "access"},
        "test-secret-key",
        expires_minutes=0,
    )
    time.sleep(1)
    result = await svc.introspect_token(token)
    assert result["active"] is False


async def test_introspect_revoked_session(svc):
    """Introspecting a token whose session was logged out returns active=False."""
    login_result = await _register_and_login(svc, suffix="revoke")
    access_token = login_result["access_token"]

    # Verify it is active first
    result = await svc.introspect_token(access_token)
    assert result["active"] is True

    # Logout (revoke session)
    await svc.logout(access_token)

    # Now introspection should return inactive
    result = await svc.introspect_token(access_token)
    assert result["active"] is False
