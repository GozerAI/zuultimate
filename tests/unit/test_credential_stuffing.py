"""Tests for Phase 3.2 -- credential stuffing defense (pwned check, username limiter, honeypot)."""

import hashlib
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from zuultimate.common.redis import RedisManager
from zuultimate.identity.risk.pwned import PwnedPasswordChecker
from zuultimate.identity.risk.username_limiter import UsernameLimiter


# -- fixtures --


@pytest.fixture
async def redis():
    mgr = RedisManager("redis://localhost:9999")
    await mgr.connect()  # will fail and fallback to in-memory
    yield mgr
    await mgr.close()


@pytest.fixture(autouse=True)
def _skip_pwned_check():
    """Override the global autouse fixture to allow real PwnedPasswordChecker tests."""
    yield


# -- PwnedPasswordChecker tests --

# SHA1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
# prefix: 5BAA6, suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
_PASSWORD_SHA1_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

_HIBP_RESPONSE_WITH_MATCH = (
    "1D2DA4053E34E76F6576ED1FB72B4C02E23:5\r\n"
    f"{_PASSWORD_SHA1_SUFFIX}:3861493\r\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD9:2\r\n"
)

_HIBP_RESPONSE_NO_MATCH = (
    "1D2DA4053E34E76F6576ED1FB72B4C02E23:5\r\n"
    "0000000000000000000000000000000000A:12\r\n"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:1\r\n"
)

_FAKE_REQUEST = httpx.Request("GET", "https://api.pwnedpasswords.com/range/5BAA6")


@pytest.mark.asyncio
async def test_pwned_checker_detects_breached():
    """Verify checker returns True when the password suffix appears in the HIBP response."""
    checker = PwnedPasswordChecker()
    mock_resp = httpx.Response(200, text=_HIBP_RESPONSE_WITH_MATCH, request=_FAKE_REQUEST)

    with patch("zuultimate.identity.risk.pwned.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        result = await checker.check("password")

    assert result is True


@pytest.mark.asyncio
async def test_pwned_checker_clean_password():
    """Verify checker returns False when the password suffix is not in the HIBP response."""
    checker = PwnedPasswordChecker()
    mock_resp = httpx.Response(200, text=_HIBP_RESPONSE_NO_MATCH, request=_FAKE_REQUEST)

    with patch("zuultimate.identity.risk.pwned.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        result = await checker.check("password")

    assert result is False


@pytest.mark.asyncio
async def test_pwned_checker_network_failure():
    """Verify checker returns False (fail open) on network errors."""
    checker = PwnedPasswordChecker()

    with patch("zuultimate.identity.risk.pwned.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        result = await checker.check("password")

    assert result is False


# -- UsernameLimiter tests --


@pytest.mark.asyncio
async def test_username_limiter_allows_under_threshold(redis):
    """Verify requests under the rate limit are allowed."""
    limiter = UsernameLimiter(redis)
    user_hash = hashlib.sha256(b"alice").hexdigest()

    for _ in range(9):
        allowed = await limiter.check(user_hash, max_attempts=10, window_seconds=300)
        assert allowed is True


@pytest.mark.asyncio
async def test_username_limiter_blocks_over_threshold(redis):
    """Verify the 11th attempt is blocked when max_attempts=10."""
    limiter = UsernameLimiter(redis)
    user_hash = hashlib.sha256(b"bob").hexdigest()

    for _ in range(10):
        await limiter.check(user_hash, max_attempts=10, window_seconds=300)

    blocked = await limiter.check(user_hash, max_attempts=10, window_seconds=300)
    assert blocked is False


@pytest.mark.asyncio
async def test_username_limiter_independent_of_ip(redis):
    """Verify different usernames have separate rate-limit buckets."""
    limiter = UsernameLimiter(redis)
    hash_a = hashlib.sha256(b"carol").hexdigest()
    hash_b = hashlib.sha256(b"dave").hexdigest()

    # Exhaust carol's limit
    for _ in range(10):
        await limiter.check(hash_a, max_attempts=10, window_seconds=300)

    carol_blocked = await limiter.check(hash_a, max_attempts=10, window_seconds=300)
    dave_allowed = await limiter.check(hash_b, max_attempts=10, window_seconds=300)

    assert carol_blocked is False
    assert dave_allowed is True


# -- Honeypot endpoint tests --


@pytest.fixture
async def _honeypot_client(test_db):
    """Minimal ASGI client with in-memory DB for honeypot endpoint tests."""
    from httpx import ASGITransport, AsyncClient as HClient

    from zuultimate.app import create_app
    from zuultimate.common.config import ZuulSettings

    app = create_app()
    settings = ZuulSettings(
        identity_db_url="sqlite+aiosqlite://",
        credential_db_url="sqlite+aiosqlite://",
        session_db_url="sqlite+aiosqlite://",
        transaction_db_url="sqlite+aiosqlite://",
        audit_db_url="sqlite+aiosqlite://",
        crm_db_url="sqlite+aiosqlite://",
        secret_key="test-secret-key",
    )
    redis = RedisManager()
    redis._available = False

    app.state.db = test_db
    app.state.settings = settings
    app.state.redis = redis

    transport = ASGITransport(app=app)
    async with HClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_honeypot_returns_200(_honeypot_client):
    """Verify the honeypot endpoint returns 200 with token-shaped payload."""
    resp = await _honeypot_client.post(
        "/v1/identity/legacy-login",
        json={"username": "attacker", "password": "letmein123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"].startswith("hp.")
    assert data["refresh_token"].startswith("hp.")
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_honeypot_emits_audit_event(test_db):
    """Verify the honeypot writes a honeypot_trigger audit event."""
    from sqlalchemy import select

    from zuultimate.identity.auth_events import AuthEventEmitter
    from zuultimate.identity.models import AuthEvent

    emitter = AuthEventEmitter(test_db)
    await emitter.emit(
        event_type="honeypot_trigger",
        ip="10.0.0.1",
        user_agent="bad-bot/1.0",
        username="attacker",
    )

    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(AuthEvent).where(AuthEvent.event_type == "honeypot_trigger")
        )
        row = result.scalar_one_or_none()

    assert row is not None
    assert row.event_type == "honeypot_trigger"
    assert row.ip_hash == hashlib.sha256(b"10.0.0.1").hexdigest()
