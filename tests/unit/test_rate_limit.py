"""Unit tests for zuultimate.common.rate_limit."""

import pytest
from unittest.mock import MagicMock

from fastapi import HTTPException

from zuultimate.common.rate_limit import RateLimiter, rate_limit_login
from zuultimate.common.redis import RedisManager


@pytest.fixture
def redis():
    """In-memory RedisManager for testing."""
    mgr = RedisManager()
    mgr._available = False
    return mgr


async def test_allows_under_limit(redis):
    limiter = RateLimiter(redis, max_requests=3, window_seconds=60)
    for _ in range(3):
        await limiter.check("key")  # should not raise


async def test_blocks_at_limit(redis):
    limiter = RateLimiter(redis, max_requests=3, window_seconds=60)
    for _ in range(3):
        await limiter.check("key")
    with pytest.raises(HTTPException) as exc_info:
        await limiter.check("key")
    assert exc_info.value.status_code == 429


async def test_separate_keys_independent(redis):
    limiter = RateLimiter(redis, max_requests=2, window_seconds=60)
    await limiter.check("a")
    await limiter.check("a")
    # Key "b" should still be allowed
    await limiter.check("b")


async def test_window_expiry(redis):
    """Requests outside the window should not count."""
    import time

    limiter = RateLimiter(redis, max_requests=2, window_seconds=1)
    await limiter.check("key")
    await limiter.check("key")
    time.sleep(1.1)
    await limiter.check("key")  # should not raise -- old entries expired


async def test_rate_limit_login_dependency():
    """rate_limit_login extracts client IP from request."""
    redis = RedisManager()
    redis._available = False
    request = MagicMock()
    request.client.host = "127.0.0.1"
    request.app.state.redis = redis
    await rate_limit_login(request)


async def test_rate_limit_login_no_client():
    """rate_limit_login handles missing client gracefully."""
    redis = RedisManager()
    redis._available = False
    request = MagicMock()
    request.client = None
    request.app.state.redis = redis
    await rate_limit_login(request)
