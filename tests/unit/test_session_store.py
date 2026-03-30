"""Tests for RedisSessionStore — tiered storage S1."""

import pytest

from zuultimate.common.redis import RedisManager
from zuultimate.infra.cache.session_store import RedisSessionStore


@pytest.fixture
def redis_manager():
    """In-memory RedisManager (no real Redis needed)."""
    mgr = RedisManager()
    # Don't call connect — stays in in-memory fallback mode
    return mgr


@pytest.fixture
def store(redis_manager):
    return RedisSessionStore(redis_manager)


# ------------------------------------------------------------------
# Session CRUD
# ------------------------------------------------------------------


class TestSessionCRUD:
    @pytest.mark.asyncio
    async def test_create_and_get_session(self, store):
        claims = {"sub": "user1", "type": "access", "gen": 0}
        await store.create_session("jti-abc", claims, ttl_seconds=300)

        result = await store.get_session("jti-abc")
        assert result is not None
        assert result["sub"] == "user1"
        assert result["gen"] == 0

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, store):
        result = await store.get_session("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_session(self, store):
        await store.create_session("jti-del", {"sub": "u1"}, 300)
        await store.delete_session("jti-del")
        result = await store.get_session("jti-del")
        assert result is None

    @pytest.mark.asyncio
    async def test_session_overwrite(self, store):
        await store.create_session("jti-ow", {"v": 1}, 300)
        await store.create_session("jti-ow", {"v": 2}, 300)
        result = await store.get_session("jti-ow")
        assert result["v"] == 2


# ------------------------------------------------------------------
# Generation-based revocation
# ------------------------------------------------------------------


class TestGenerationRevocation:
    @pytest.mark.asyncio
    async def test_initial_generation_is_zero(self, store):
        gen = await store.get_generation("new-user")
        assert gen == 0

    @pytest.mark.asyncio
    async def test_revoke_all_increments_generation(self, store):
        await store.revoke_all_sessions("user-x")
        gen = await store.get_generation("user-x")
        assert gen == 1

        await store.revoke_all_sessions("user-x")
        gen = await store.get_generation("user-x")
        assert gen == 2

    @pytest.mark.asyncio
    async def test_old_generation_token_rejected(self, store):
        # Token issued at gen=0
        await store.create_session("jti-old", {"sub": "u1", "gen": 0}, 300)

        # User revokes all — gen becomes 1
        await store.revoke_all_sessions("u1")

        # validate_token_session with old gen should fail
        valid = await store.validate_token_session("u1", "jti-old", gen=0)
        assert valid is False

    @pytest.mark.asyncio
    async def test_current_generation_token_accepted(self, store):
        await store.create_session("jti-cur", {"sub": "u2", "gen": 0}, 300)
        valid = await store.validate_token_session("u2", "jti-cur", gen=0)
        assert valid is True


# ------------------------------------------------------------------
# Targeted single-session revocation
# ------------------------------------------------------------------


class TestSingleSessionRevocation:
    @pytest.mark.asyncio
    async def test_revoke_single_session(self, store):
        await store.create_session("jti-a", {"sub": "u1"}, 300)
        await store.create_session("jti-b", {"sub": "u1"}, 300)

        await store.revoke_session("u1", "jti-a", gen=0)

        assert await store.is_session_denied("u1", "jti-a", 0) is True
        assert await store.is_session_denied("u1", "jti-b", 0) is False

    @pytest.mark.asyncio
    async def test_denied_session_fails_validation(self, store):
        await store.create_session("jti-denied", {"sub": "u3"}, 300)
        await store.revoke_session("u3", "jti-denied", gen=0)

        valid = await store.validate_token_session("u3", "jti-denied", gen=0)
        assert valid is False

    @pytest.mark.asyncio
    async def test_non_denied_session_passes(self, store):
        assert await store.is_session_denied("u1", "jti-x", 0) is False


# ------------------------------------------------------------------
# validate_token_session combined checks
# ------------------------------------------------------------------


class TestValidateTokenSession:
    @pytest.mark.asyncio
    async def test_valid_session(self, store):
        await store.create_session("jti-v", {"sub": "u1", "gen": 0}, 300)
        assert await store.validate_token_session("u1", "jti-v", 0) is True

    @pytest.mark.asyncio
    async def test_missing_session_returns_false(self, store):
        result = await store.validate_token_session("u1", "jti-missing", 0)
        assert result is False

    @pytest.mark.asyncio
    async def test_stale_gen_returns_false(self, store):
        await store.create_session("jti-sg", {"sub": "u1"}, 300)
        await store.revoke_all_sessions("u1")
        assert await store.validate_token_session("u1", "jti-sg", 0) is False


# ------------------------------------------------------------------
# Tenant config cache
# ------------------------------------------------------------------


class TestTenantCache:
    @pytest.mark.asyncio
    async def test_cache_and_get_tenant(self, store):
        data = {"name": "Acme", "plan": "pro"}
        await store.cache_tenant("t-1", data)
        result = await store.get_cached_tenant("t-1")
        assert result == data

    @pytest.mark.asyncio
    async def test_tenant_cache_miss(self, store):
        result = await store.get_cached_tenant("t-missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_tenant(self, store):
        await store.cache_tenant("t-2", {"name": "Corp"})
        await store.invalidate_tenant("t-2")
        result = await store.get_cached_tenant("t-2")
        assert result is None


# ------------------------------------------------------------------
# Device posture cache
# ------------------------------------------------------------------


class TestPostureCache:
    @pytest.mark.asyncio
    async def test_cache_and_get_posture(self, store):
        data = {"os": "linux", "score": 85}
        await store.cache_posture("dev-1", data)
        result = await store.get_cached_posture("dev-1")
        assert result == data

    @pytest.mark.asyncio
    async def test_posture_cache_miss(self, store):
        result = await store.get_cached_posture("dev-missing")
        assert result is None


# ------------------------------------------------------------------
# Graceful fallback when Redis is broken
# ------------------------------------------------------------------


class TestGracefulFallback:
    @pytest.mark.asyncio
    async def test_broken_redis_get_session_returns_none(self):
        """When RedisManager internals raise, methods degrade gracefully."""
        mgr = RedisManager()
        store = RedisSessionStore(mgr)

        # Poison the internal store to simulate breakage
        original_get = mgr.get

        async def _broken_get(key):
            raise ConnectionError("Redis down")

        mgr.get = _broken_get  # type: ignore[assignment]

        result = await store.get_session("jti-x")
        assert result is None
        mgr.get = original_get  # restore

    @pytest.mark.asyncio
    async def test_broken_redis_create_session_noop(self):
        mgr = RedisManager()
        store = RedisSessionStore(mgr)

        async def _broken_setex(key, ttl, val):
            raise ConnectionError("Redis down")

        mgr.setex = _broken_setex  # type: ignore[assignment]

        # Should not raise
        await store.create_session("jti-y", {"sub": "u1"}, 300)
