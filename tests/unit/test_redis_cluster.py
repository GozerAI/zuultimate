"""Tests for Redis Cluster configuration with circuit breaker."""

import time

import pytest

from zuultimate.infra.cache.cluster import (
    MEMORY_CRITICAL_THRESHOLD,
    MEMORY_WARNING_THRESHOLD,
    RedisClusterConfig,
)


class FakeRedis:
    """Minimal fake Redis for testing the cluster wrapper."""

    def __init__(self, fail_after: int = -1):
        self._mem_store: dict[str, str] = {}
        self._mem_expiry: dict[str, float] = {}
        self._call_count = 0
        self._fail_after = fail_after  # fail after N successful calls (-1 = never fail)

    async def get(self, key: str) -> str | None:
        self._call_count += 1
        if 0 <= self._fail_after < self._call_count:
            raise ConnectionError("Redis unavailable")
        return self._mem_store.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self._call_count += 1
        if 0 <= self._fail_after < self._call_count:
            raise ConnectionError("Redis unavailable")
        self._mem_store[key] = value
        self._mem_expiry[key] = time.time() + ttl

    async def delete(self, key: str) -> None:
        self._call_count += 1
        if 0 <= self._fail_after < self._call_count:
            raise ConnectionError("Redis unavailable")
        self._mem_store.pop(key, None)
        self._mem_expiry.pop(key, None)


class FakeFallbackDB:
    """Fake fallback DB for testing."""

    def __init__(self):
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)


# ── Basic get/set ──


async def test_get_set_through_wrapper():
    """get/set should work through the wrapper."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)

    result = await cluster.set("key1", "value1", ttl=60)
    assert result is True

    value = await cluster.get("key1")
    assert value == "value1"


async def test_delete_through_wrapper():
    """delete should remove the key."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)

    await cluster.set("key1", "value1", ttl=60)
    result = await cluster.delete("key1")
    assert result is True

    value = await cluster.get("key1")
    assert value is None


# ── Circuit breaker ──


async def test_circuit_opens_after_threshold_failures():
    """Circuit breaker should open after N consecutive failures."""
    redis = FakeRedis(fail_after=0)  # fail immediately
    cluster = RedisClusterConfig(redis)
    cluster._failure_threshold = 3

    # Each failure increments count
    for _ in range(3):
        await cluster.get("key1")

    assert cluster._circuit_open is True


async def test_circuit_recovers_after_timeout():
    """Circuit breaker should recover after the recovery timeout."""
    redis = FakeRedis(fail_after=0)
    cluster = RedisClusterConfig(redis)
    cluster._failure_threshold = 1
    cluster._recovery_timeout = 0.1  # 100ms for testing

    # Trigger circuit open
    await cluster.get("key1")
    assert cluster._circuit_open is True

    # Wait for recovery
    time.sleep(0.15)

    # Circuit should be half-open (will try again)
    assert cluster._is_circuit_open() is False


async def test_fallback_none_when_no_fallback_db():
    """When Redis fails and no fallback_db, get should return None."""
    redis = FakeRedis(fail_after=0)
    cluster = RedisClusterConfig(redis, fallback_db=None)

    result = await cluster.get("key1")
    assert result is None


async def test_fallback_to_db_when_redis_fails():
    """When Redis fails, get should fall back to DB."""
    redis = FakeRedis(fail_after=0)
    fallback = FakeFallbackDB()
    fallback._store["key1"] = "from_db"

    cluster = RedisClusterConfig(redis, fallback_db=fallback)

    result = await cluster.get("key1")
    assert result == "from_db"


async def test_set_returns_false_when_circuit_open():
    """set should return False when circuit is open."""
    redis = FakeRedis(fail_after=0)
    cluster = RedisClusterConfig(redis)
    cluster._circuit_open = True
    cluster._last_failure = time.time()

    result = await cluster.set("key1", "value1", ttl=60)
    assert result is False


# ── Memory management ──


async def test_check_memory_returns_stats():
    """check_memory should return a dict with expected keys."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)

    stats = await cluster.check_memory()
    assert "used_memory" in stats
    assert "max_memory" in stats
    assert "usage_ratio" in stats
    assert "alert_level" in stats
    assert "circuit_open" in stats
    assert stats["circuit_open"] is False


async def test_check_memory_circuit_open():
    """check_memory should return unknown alert when circuit is open."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)
    cluster._circuit_open = True
    cluster._last_failure = time.time()

    stats = await cluster.check_memory()
    assert stats["alert_level"] == "unknown"
    assert stats["circuit_open"] is True


async def test_get_key_counts_from_memory_store():
    """get_key_counts should count keys by prefix from in-memory store."""
    redis = FakeRedis()
    redis._mem_store = {
        "session:abc": "1",
        "session:def": "2",
        "jwks:cache": "3",
        "rate_limit:ip1": "4",
    }
    cluster = RedisClusterConfig(redis)

    counts = await cluster.get_key_counts()
    assert counts["session"] == 2
    assert counts["jwks"] == 1
    assert counts["rate_limit"] == 1


async def test_get_key_counts_empty_when_circuit_open():
    """get_key_counts should return empty dict when circuit is open."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)
    cluster._circuit_open = True
    cluster._last_failure = time.time()

    counts = await cluster.get_key_counts()
    assert counts == {}


# ── Read preference ──


async def test_read_preference_replica():
    """Read preference should be 'replica' for tenant_config, posture_cache, jwks_cache."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)

    assert cluster.get_read_preference("tenant_config") == "replica"
    assert cluster.get_read_preference("posture_cache") == "replica"
    assert cluster.get_read_preference("jwks_cache") == "replica"


async def test_read_preference_primary():
    """Read preference should be 'primary' for session, rate_limit, deny_list."""
    redis = FakeRedis()
    cluster = RedisClusterConfig(redis)

    assert cluster.get_read_preference("session") == "primary"
    assert cluster.get_read_preference("rate_limit") == "primary"
    assert cluster.get_read_preference("deny_list") == "primary"
