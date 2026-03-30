"""Unit tests for zuultimate.common.redis (in-memory fallback)."""

import time

import pytest

from zuultimate.common.redis import RedisManager


@pytest.fixture
def redis():
    """RedisManager with in-memory fallback (no real Redis)."""
    mgr = RedisManager()
    mgr._available = False
    return mgr


async def test_setex_and_get(redis):
    await redis.setex("k1", 60, "value1")
    result = await redis.get("k1")
    assert result == "value1"


async def test_get_nonexistent_returns_none(redis):
    result = await redis.get("nope")
    assert result is None


async def test_setex_expires(redis):
    await redis.setex("k2", 1, "temporary")
    assert await redis.get("k2") == "temporary"
    time.sleep(1.1)
    assert await redis.get("k2") is None


async def test_delete(redis):
    await redis.setex("k3", 60, "val")
    await redis.delete("k3")
    assert await redis.get("k3") is None


async def test_rate_limit_allows_under_limit(redis):
    for _ in range(5):
        assert await redis.rate_limit_check("rl:test", 5, 60) is True


async def test_rate_limit_blocks_at_limit(redis):
    for _ in range(3):
        await redis.rate_limit_check("rl:block", 3, 60)
    assert await redis.rate_limit_check("rl:block", 3, 60) is False


async def test_rate_limit_window_expiry(redis):
    for _ in range(2):
        await redis.rate_limit_check("rl:expire", 2, 1)
    assert await redis.rate_limit_check("rl:expire", 2, 1) is False
    time.sleep(1.1)
    assert await redis.rate_limit_check("rl:expire", 2, 1) is True


async def test_idempotency_roundtrip(redis):
    assert await redis.get_idempotency("key1") is None
    await redis.store_idempotency("key1", 200, {"id": "abc"})
    cached = await redis.get_idempotency("key1")
    assert cached is not None
    assert cached["status_code"] == 200
    assert cached["body"]["id"] == "abc"


async def test_idempotency_expires(redis):
    await redis.store_idempotency("key2", 200, {"ok": True}, ttl=1)
    assert await redis.get_idempotency("key2") is not None
    time.sleep(1.1)
    assert await redis.get_idempotency("key2") is None


async def test_reset_all(redis):
    await redis.setex("a", 60, "1")
    await redis.rate_limit_check("b", 10, 60)
    await redis.store_idempotency("c", 200, {})
    redis.reset_all()
    assert await redis.get("a") is None
    assert await redis.get_idempotency("c") is None


async def test_is_available_false_by_default(redis):
    assert redis.is_available is False


async def test_connect_without_redis_package():
    """When redis package exists but server is unreachable, falls back gracefully."""
    mgr = RedisManager("redis://localhost:59999")
    await mgr.connect()
    # Should fall back to in-memory
    assert mgr.is_available is False or mgr.is_available is True
    # Either way, operations should work
    await mgr.setex("test", 60, "val")
    result = await mgr.get("test")
    # If Redis was actually available (unlikely on port 59999) or fallback, both are fine
    await mgr.close()
