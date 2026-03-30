"""Tests for caching layers: JWT, API key, RBAC, vault secret caches."""

import asyncio
import time

import pytest

from zuultimate.performance.caching import (
    APIKeyCache,
    JWTValidationCache,
    RBACPermissionCache,
    TTLCache,
    VaultSecretCache,
)


class TestTTLCache:
    def test_put_and_get(self):
        cache = TTLCache(default_ttl=60.0)
        cache.put("k1", "v1")
        assert cache.get("k1") == "v1"

    def test_miss_returns_none(self):
        cache = TTLCache()
        assert cache.get("nonexistent") is None

    def test_ttl_expiry(self):
        cache = TTLCache(default_ttl=0.01)
        cache.put("k1", "v1")
        time.sleep(0.02)
        assert cache.get("k1") is None

    def test_custom_ttl_per_entry(self):
        cache = TTLCache(default_ttl=60.0)
        cache.put("k1", "v1", ttl=0.01)
        time.sleep(0.02)
        assert cache.get("k1") is None

    def test_invalidate(self):
        cache = TTLCache()
        cache.put("k1", "v1")
        assert cache.invalidate("k1") is True
        assert cache.get("k1") is None

    def test_invalidate_missing(self):
        cache = TTLCache()
        assert cache.invalidate("missing") is False

    def test_invalidate_prefix(self):
        cache = TTLCache()
        cache.put("user:1:a", "v1")
        cache.put("user:1:b", "v2")
        cache.put("user:2:a", "v3")
        removed = cache.invalidate_prefix("user:1:")
        assert removed == 2
        assert cache.get("user:1:a") is None
        assert cache.get("user:2:a") == "v3"

    def test_max_size_eviction(self):
        cache = TTLCache(max_size=3, default_ttl=60.0)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.put("d", 4)  # should evict oldest
        assert cache.size == 3
        assert cache.get("d") == 4

    def test_clear(self):
        cache = TTLCache()
        cache.put("k1", "v1")
        cache.put("k2", "v2")
        cache.clear()
        assert cache.size == 0

    def test_stats(self):
        cache = TTLCache()
        cache.put("k1", "v1")
        cache.get("k1")  # hit
        cache.get("miss")  # miss
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["size"] == 1


class TestJWTValidationCache:
    """Item #37: JWT validation result caching with TTL."""

    def test_cache_and_retrieve(self):
        cache = JWTValidationCache(ttl=60.0)
        payload = {"sub": "user1", "exp": 999}
        cache.put("token123", payload)
        assert cache.get("token123") == payload

    def test_miss(self):
        cache = JWTValidationCache()
        assert cache.get("missing") is None

    def test_invalidate_token(self):
        cache = JWTValidationCache()
        cache.put("token123", {"sub": "user1"})
        assert cache.invalidate("token123") is True
        assert cache.get("token123") is None

    def test_invalidate_user(self):
        cache = JWTValidationCache()
        cache.put("t1", {"sub": "user1"})
        cache.put("t2", {"sub": "user1"})
        cache.put("t3", {"sub": "user2"})
        removed = cache.invalidate_user("user1")
        assert removed == 2
        assert cache.get("t3") is not None

    def test_ttl_expiry(self):
        cache = JWTValidationCache(ttl=0.01)
        cache.put("token", {"sub": "u"})
        time.sleep(0.02)
        assert cache.get("token") is None

    def test_stats(self):
        cache = JWTValidationCache()
        cache.put("t", {"sub": "u"})
        cache.get("t")
        cache.get("miss")
        stats = cache.stats
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1


class TestAPIKeyCache:
    """Item #44: API key validation cache with background refresh."""

    def test_put_and_get(self):
        cache = APIKeyCache(ttl=60.0)
        cache.put("gzr_abc1", {"tenant_id": "t1"})
        assert cache.get("gzr_abc1") == {"tenant_id": "t1"}

    def test_miss(self):
        cache = APIKeyCache()
        assert cache.get("missing") is None

    def test_invalidate(self):
        cache = APIKeyCache()
        cache.put("gzr_abc1", {"tenant_id": "t1"})
        assert cache.invalidate("gzr_abc1") is True
        assert cache.get("gzr_abc1") is None

    def test_needs_refresh_false_when_fresh(self):
        cache = APIKeyCache(ttl=60.0, refresh_after=30.0)
        cache.put("gzr_abc1", {"tenant_id": "t1"})
        assert cache.needs_refresh("gzr_abc1") is False

    def test_needs_refresh_true_when_stale(self):
        cache = APIKeyCache(ttl=60.0, refresh_after=0.01)
        cache.put("gzr_abc1", {"tenant_id": "t1"})
        time.sleep(0.02)
        assert cache.needs_refresh("gzr_abc1") is True

    def test_needs_refresh_false_when_missing(self):
        cache = APIKeyCache()
        assert cache.needs_refresh("missing") is False

    async def test_schedule_refresh(self):
        cache = APIKeyCache(ttl=60.0)
        cache.put("gzr_abc1", {"tenant_id": "old"})

        async def refresh_fn(prefix):
            return {"tenant_id": "refreshed"}

        cache.schedule_refresh("gzr_abc1", refresh_fn)
        await asyncio.sleep(0.1)
        assert cache.get("gzr_abc1") == {"tenant_id": "refreshed"}


class TestRBACPermissionCache:
    """Item #59: RBAC permission cache per user."""

    def test_put_and_get(self):
        cache = RBACPermissionCache()
        result = {"allowed": True, "reason": "Allowed by admin"}
        cache.put("user1", "vault/*", "read", result)
        assert cache.get("user1", "vault/*", "read") == result

    def test_miss(self):
        cache = RBACPermissionCache()
        assert cache.get("user1", "vault/*", "read") is None

    def test_different_resources(self):
        cache = RBACPermissionCache()
        cache.put("u1", "vault/*", "read", {"allowed": True, "reason": "ok"})
        assert cache.get("u1", "vault/*", "write") is None

    def test_invalidate_user(self):
        cache = RBACPermissionCache()
        cache.put("u1", "r1", "a1", {"allowed": True, "reason": "ok"})
        cache.put("u1", "r2", "a2", {"allowed": True, "reason": "ok"})
        cache.put("u2", "r1", "a1", {"allowed": True, "reason": "ok"})
        removed = cache.invalidate_user("u1")
        assert removed == 2
        assert cache.get("u2", "r1", "a1") is not None

    def test_clear(self):
        cache = RBACPermissionCache()
        cache.put("u1", "r1", "a1", {"allowed": True, "reason": "ok"})
        cache.clear()
        assert cache.get("u1", "r1", "a1") is None

    def test_ttl_expiry(self):
        cache = RBACPermissionCache(ttl=0.01)
        cache.put("u1", "r1", "a1", {"allowed": True, "reason": "ok"})
        time.sleep(0.02)
        assert cache.get("u1", "r1", "a1") is None


class TestVaultSecretCache:
    """Item #68: Vault secret cache with rotation-triggered invalidation."""

    def test_put_and_get(self):
        cache = VaultSecretCache()
        cache.put("blob1", "owner1", {"plaintext": "secret"})
        assert cache.get("blob1", "owner1") == {"plaintext": "secret"}

    def test_miss(self):
        cache = VaultSecretCache()
        assert cache.get("blob1") is None

    def test_invalidate_single(self):
        cache = VaultSecretCache()
        cache.put("blob1", "owner1", {"plaintext": "secret"})
        assert cache.invalidate("blob1", "owner1") is True
        assert cache.get("blob1", "owner1") is None

    def test_rotation_clears_all(self):
        cache = VaultSecretCache()
        cache.put("blob1", "o1", {"plaintext": "s1"})
        cache.put("blob2", "o2", {"plaintext": "s2"})
        cache.on_rotation()
        assert cache.get("blob1", "o1") is None
        assert cache.get("blob2", "o2") is None

    def test_rotation_increments_generation(self):
        cache = VaultSecretCache()
        assert cache.stats["rotation_generation"] == 0
        cache.on_rotation()
        assert cache.stats["rotation_generation"] == 1

    def test_new_entries_after_rotation(self):
        cache = VaultSecretCache()
        cache.put("blob1", "o1", {"plaintext": "old"})
        cache.on_rotation()
        cache.put("blob1", "o1", {"plaintext": "new"})
        assert cache.get("blob1", "o1") == {"plaintext": "new"}
