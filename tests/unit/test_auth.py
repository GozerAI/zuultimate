"""Unit tests for zuultimate.common.auth -- JWT Bearer auth middleware."""

import hashlib

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException

from zuultimate.common.auth import get_current_user
from zuultimate.common.security import create_jwt


SECRET = "test-secret-key"


def _make_request_mock(settings=None, db=None):
    """Build a mock Request object with app.state."""
    request = MagicMock()
    request.app.state.settings = settings or MagicMock(secret_key=SECRET)
    request.app.state.db = db or MagicMock()
    return request


def _make_credentials(token: str):
    creds = MagicMock()
    creds.credentials = token
    return creds


async def test_valid_access_token(test_db, test_settings):
    """Valid access token with matching session and active user should succeed."""
    from zuultimate.identity.service import IdentityService

    svc = IdentityService(test_db, test_settings)
    await svc.register("auth@test.com", "authuser", "password123")
    login_result = await svc.login("authuser", "password123")
    access_token = login_result["access_token"]

    request = MagicMock()
    request.app.state.settings = test_settings
    request.app.state.db = test_db

    creds = _make_credentials(access_token)
    result = await get_current_user(request, creds)
    assert result["username"] == "authuser"
    assert "user_id" in result


async def test_expired_token_rejected():
    """Expired JWT should raise 401."""
    token = create_jwt(
        {"sub": "u1", "username": "u", "type": "access"}, SECRET, expires_minutes=0,
    )
    import time
    time.sleep(1)

    request = _make_request_mock()
    creds = _make_credentials(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


async def test_refresh_token_rejected():
    """Refresh-type token should be rejected by access-only middleware."""
    token = create_jwt(
        {"sub": "u1", "username": "u", "type": "refresh"}, SECRET,
    )
    request = _make_request_mock()
    creds = _make_credentials(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401
    assert "token type" in exc_info.value.detail


async def test_garbage_token_rejected():
    """Completely invalid token string should raise 401."""
    request = _make_request_mock()
    creds = _make_credentials("not.a.jwt")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


async def test_missing_sub_rejected():
    """Token without 'sub' claim should raise 401."""
    token = create_jwt({"username": "u", "type": "access"}, SECRET)
    request = _make_request_mock()
    creds = _make_credentials(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401
    assert "payload" in exc_info.value.detail
