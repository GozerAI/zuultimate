"""Auth hardening tests -- JWT edge cases, token manipulation, boundary conditions."""

import time

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from zuultimate.common.security import create_jwt, decode_jwt
from zuultimate.common.auth import get_current_user, get_service_caller
from zuultimate.common.config import ZuulSettings
from fastapi import HTTPException

SECRET = "test-secret-key"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_request(settings=None, db=None):
    """Build a mock Request object with app.state."""
    request = MagicMock()
    request.app.state.settings = settings or MagicMock(secret_key=SECRET)
    request.app.state.db = db or MagicMock()
    # Ensure no redis / session_store / key_manager to stay on JWT+DB path
    request.app.state.redis = None
    request.app.state.session_store = None
    request.app.state.key_manager = None
    return request


def _mock_creds(token):
    c = MagicMock()
    c.credentials = token
    return c


# ---------------------------------------------------------------------------
# 1. Empty-string token
# ---------------------------------------------------------------------------


async def test_empty_string_token():
    """Empty token string should raise 401 (decode will fail)."""
    request = _mock_request()
    creds = _mock_creds("")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 2. None-ish credential
# ---------------------------------------------------------------------------


async def test_none_token():
    """None credential value should raise 401."""
    request = _mock_request()
    # HTTPBearer would normally reject this, but test the middleware directly
    creds = _mock_creds(None)
    with pytest.raises((HTTPException, AttributeError, TypeError)):
        await get_current_user(request, creds)


# ---------------------------------------------------------------------------
# 3. Wrong secret
# ---------------------------------------------------------------------------


async def test_token_wrong_secret():
    """JWT signed with a different secret must be rejected."""
    token = create_jwt(
        {"sub": "u1", "username": "alice", "type": "access"},
        "different-secret-key",
    )
    request = _mock_request()
    creds = _mock_creds(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 4. Missing 'sub' claim
# ---------------------------------------------------------------------------


async def test_token_missing_sub_claim():
    """JWT without 'sub' should raise 401 with 'payload' detail."""
    token = create_jwt({"username": "alice", "type": "access"}, SECRET)
    request = _mock_request()
    creds = _mock_creds(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401
    assert "payload" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 5. Missing 'type' claim
# ---------------------------------------------------------------------------


async def test_token_missing_type_claim():
    """JWT without 'type' claim should be rejected (type != 'access')."""
    token = create_jwt({"sub": "u1", "username": "alice"}, SECRET)
    request = _mock_request()
    creds = _mock_creds(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401
    assert "token type" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# 6. Future iat (clock skew)
# ---------------------------------------------------------------------------


async def test_token_future_iat():
    """JWT with iat in the future is rejected by PyJWT (ImmatureSignatureError).
    get_current_user should surface this as a 401."""
    from datetime import datetime, timedelta, timezone
    import jwt as pyjwt

    future_iat = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {
        "sub": "u1",
        "username": "alice",
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        "iat": future_iat,
        "jti": "abc123",
        "iss": "zuultimate",
        "aud": "zuultimate-api",
    }
    token = pyjwt.encode(payload, SECRET, algorithm="HS256")

    request = _mock_request()
    creds = _mock_creds(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 7. Token at exact expiry boundary
# ---------------------------------------------------------------------------


async def test_token_at_exact_expiry():
    """Token created with 0 expires_minutes should be expired immediately (or
    within the 1-second test window)."""
    token = create_jwt(
        {"sub": "u1", "username": "alice", "type": "access"},
        SECRET,
        expires_minutes=0,
    )
    # Give it a moment to definitely expire
    time.sleep(1)
    request = _mock_request()
    creds = _mock_creds(token)
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 8. Extra claims
# ---------------------------------------------------------------------------


async def test_token_with_extra_claims():
    """JWT with unexpected extra claims should still decode if otherwise valid."""
    token = create_jwt(
        {
            "sub": "u1",
            "username": "alice",
            "type": "access",
            "custom_role": "admin",
            "org_id": 42,
        },
        SECRET,
    )
    decoded = decode_jwt(token, SECRET)
    assert decoded["sub"] == "u1"
    assert decoded["custom_role"] == "admin"
    assert decoded["org_id"] == 42


# ---------------------------------------------------------------------------
# 9. Unicode username
# ---------------------------------------------------------------------------


async def test_token_unicode_username():
    """JWT with unicode characters in username should encode/decode correctly."""
    token = create_jwt(
        {"sub": "u1", "username": "\u00e9l\u00e8ve_\u4e16\u754c_\u041f\u0440\u0438\u0432\u0435\u0442", "type": "access"},
        SECRET,
    )
    decoded = decode_jwt(token, SECRET)
    assert decoded["username"] == "\u00e9l\u00e8ve_\u4e16\u754c_\u041f\u0440\u0438\u0432\u0435\u0442"


# ---------------------------------------------------------------------------
# 10. API key wrong prefix
# ---------------------------------------------------------------------------


async def test_api_key_wrong_prefix():
    """Token that does NOT start with 'gzr_' should go through JWT path, not
    API key path, and fail JWT decode."""
    request = _mock_request()
    creds = _mock_creds("badprefix_abcdef1234567890")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, creds)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 11. Service token -- empty
# ---------------------------------------------------------------------------


async def test_service_token_empty():
    """Empty X-Service-Token header should raise 401."""
    request = MagicMock()
    request.headers.get.return_value = ""
    request.app.state.settings = MagicMock(service_token="real-service-token")
    with pytest.raises(HTTPException) as exc_info:
        await get_service_caller(request)
    assert exc_info.value.status_code == 401
    assert "service token" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# 12. Production validation -- insecure defaults rejected
# ---------------------------------------------------------------------------


def test_settings_production_validation():
    """validate_for_production() should raise with insecure defaults in production."""
    settings = ZuulSettings(environment="production")
    with pytest.raises(RuntimeError, match="ZUUL_SECRET_KEY"):
        settings.validate_for_production()


# ---------------------------------------------------------------------------
# 13. Production validation -- passes with proper config
# ---------------------------------------------------------------------------


def test_settings_production_validation_passes():
    """validate_for_production() should succeed with all secure values set."""
    settings = ZuulSettings(
        environment="production",
        secret_key="a-very-secure-key-that-is-not-default",
        vault_salt="custom-vault-salt-unique",
        mfa_salt="custom-mfa-salt-unique",
        password_vault_salt="custom-pw-salt-unique",
    )
    # Should not raise
    settings.validate_for_production()


# ---------------------------------------------------------------------------
# 14. Very large payload
# ---------------------------------------------------------------------------


async def test_jwt_very_long_payload():
    """JWT with ~10KB of extra claims should still encode/decode correctly."""
    large_value = "x" * 10_000
    token = create_jwt(
        {"sub": "u1", "username": "alice", "type": "access", "big": large_value},
        SECRET,
    )
    decoded = decode_jwt(token, SECRET)
    assert decoded["big"] == large_value
    assert len(decoded["big"]) == 10_000


# ---------------------------------------------------------------------------
# 15. Concurrent logins (integration — uses test_db + test_settings)
# ---------------------------------------------------------------------------


async def test_concurrent_logins(test_db, test_settings):
    """Two logins with the same credentials should each produce valid tokens."""
    from zuultimate.identity.service import IdentityService

    svc = IdentityService(test_db, test_settings)
    await svc.register("concurrent@test.com", "concuser", "password123")

    login1 = await svc.login("concuser", "password123")
    login2 = await svc.login("concuser", "password123")

    assert login1["access_token"] != login2["access_token"]

    # Both tokens should be independently valid
    for tok in [login1["access_token"], login2["access_token"]]:
        request = MagicMock()
        request.app.state.settings = test_settings
        request.app.state.db = test_db
        request.app.state.redis = None
        request.app.state.session_store = None
        request.app.state.key_manager = None

        creds = _mock_creds(tok)
        result = await get_current_user(request, creds)
        assert result["username"] == "concuser"
