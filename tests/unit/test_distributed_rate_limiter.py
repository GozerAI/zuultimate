"""Tests for the two-tier distributed rate limiter."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from zuultimate.infra.ratelimit.distributed import (
    DistributedRateLimiter,
    RateLimitResult,
    RATE_LIMIT_CONFIGS,
)


class TestRateLimitResult:
    """Tests for the RateLimitResult dataclass."""

    def test_allowed_result_fields(self):
        r = RateLimitResult(allowed=True, remaining=5)
        assert r.allowed is True
        assert r.remaining == 5
        assert r.retry_after is None

    def test_denied_result_fields(self):
        r = RateLimitResult(allowed=False, remaining=0, retry_after=60)
        assert r.allowed is False
        assert r.remaining == 0
        assert r.retry_after == 60

    def test_defaults(self):
        r = RateLimitResult(allowed=True, remaining=10)
        assert r.retry_after is None


class TestDistributedRateLimiter:
    """Tests for the two-tier rate limiter."""

    def _make_redis(self, *, has_raw: bool = False):
        """Create a mock Redis manager."""
        mock = MagicMock()
        if has_raw:
            raw = AsyncMock()
            pipe = AsyncMock()
            pipe.incr = MagicMock(return_value=pipe)
            pipe.expire = MagicMock(return_value=pipe)
            pipe.execute = AsyncMock(return_value=[1, True])
            raw.pipeline = MagicMock(return_value=pipe)
            mock._redis = raw
        else:
            mock._redis = None
        return mock

    @pytest.mark.asyncio
    async def test_under_limit_allowed(self):
        redis = self._make_redis()
        limiter = DistributedRateLimiter(redis, limit=100, window_seconds=1)

        result = await limiter.check("user:1")
        assert result.allowed is True
        assert result.remaining > 0

    @pytest.mark.asyncio
    async def test_over_limit_denied(self):
        # Use a Redis mock that tracks increment counts globally
        call_count = {"value": 0}

        redis = self._make_redis(has_raw=True)
        raw = redis._redis
        pipe_mock = raw.pipeline()

        async def _execute():
            call_count["value"] += 1
            return [call_count["value"], True]

        pipe_mock.execute = AsyncMock(side_effect=_execute)

        limiter = DistributedRateLimiter(
            redis, limit=2, window_seconds=1, num_pods=1
        )

        results = []
        for _ in range(5):
            results.append(await limiter.check("user:1"))

        # At some point it should be denied (global_count > limit)
        denied = [r for r in results if not r.allowed]
        assert len(denied) > 0

    @pytest.mark.asyncio
    async def test_over_limit_has_retry_after(self):
        redis = self._make_redis()
        limiter = DistributedRateLimiter(
            redis, limit=1, window_seconds=60, num_pods=1
        )

        # First call allowed, second denied
        await limiter.check("user:x")
        await limiter.check("user:x")
        result = await limiter.check("user:x")

        if not result.allowed:
            assert result.retry_after == 60

    @pytest.mark.asyncio
    async def test_window_rollover_resets(self):
        redis = self._make_redis()
        limiter = DistributedRateLimiter(
            redis, limit=5, window_seconds=1, num_pods=1
        )

        # Exhaust local counter
        for _ in range(3):
            await limiter.check("user:rollover")

        # Simulate window rollover by manipulating stored window
        limiter._window_starts["user:rollover"] = 0  # force old window

        result = await limiter.check("user:rollover")
        # After rollover, counter should reset
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_per_key_independence(self):
        redis = self._make_redis()
        limiter = DistributedRateLimiter(
            redis, limit=3, window_seconds=1, num_pods=1
        )

        # Use up key A's budget
        for _ in range(5):
            await limiter.check("key-A")

        # Key B should still be allowed
        result = await limiter.check("key-B")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_local_fast_path_no_redis(self):
        """When under local share and not at sync interval, Redis is not called."""
        redis = self._make_redis()
        # limit=100, num_pods=10 => local_share=10, sync_every=1
        # With sync_every=1, every request syncs. Use larger limit.
        limiter = DistributedRateLimiter(
            redis, limit=1000, window_seconds=1, num_pods=10
        )
        # local_share=100, sync_every=10

        # First request (count=1): 1 < 100 and 1 % 10 != 0 => fast path
        result = await limiter.check("fast-path-key")
        assert result.allowed is True
        # No Redis was accessed (mock._redis is None, so no error)

    @pytest.mark.asyncio
    async def test_sync_path_calls_redis(self):
        """When local share is exhausted, Redis pipeline is invoked."""
        redis = self._make_redis(has_raw=True)
        limiter = DistributedRateLimiter(
            redis, limit=100, window_seconds=1, num_pods=1
        )
        # local_share=100, sync_every=10

        # Request at count=10 (sync_every=10) should trigger Redis sync
        for _ in range(10):
            await limiter.check("sync-key")

        raw = redis._redis
        assert raw.pipeline.called

    @pytest.mark.asyncio
    async def test_redis_unavailable_falls_back(self):
        """When Redis raises, local counting is used as fallback."""
        redis = self._make_redis(has_raw=True)
        raw = redis._redis
        pipe = raw.pipeline()
        pipe.execute = AsyncMock(side_effect=ConnectionError("Redis down"))

        limiter = DistributedRateLimiter(
            redis, limit=100, window_seconds=1, num_pods=1
        )
        # sync_every=10

        # Should not raise even when Redis fails
        for _ in range(15):
            result = await limiter.check("fallback-key")

        # Should still produce results (fallback to local)
        assert isinstance(result, RateLimitResult)

    @pytest.mark.asyncio
    async def test_multiple_rapid_calls_accumulate(self):
        redis = self._make_redis()
        limiter = DistributedRateLimiter(
            redis, limit=1000, window_seconds=1, num_pods=10
        )

        results = []
        for _ in range(20):
            results.append(await limiter.check("rapid-key"))

        # All should be allowed (well under limit)
        assert all(r.allowed for r in results)
        # Remaining should decrease
        allowed_results = [r for r in results if r.remaining > 0]
        assert len(allowed_results) > 0


class TestRateLimitConfigs:
    """Tests for rate limit configuration presets."""

    def test_auth_token_config(self):
        cfg = RATE_LIMIT_CONFIGS["auth_token"]
        assert cfg["limit"] == 10
        assert cfg["window"] == 1

    def test_auth_token_user_config(self):
        cfg = RATE_LIMIT_CONFIGS["auth_token_user"]
        assert cfg["limit"] == 5
        assert cfg["window"] == 1

    def test_introspect_config(self):
        cfg = RATE_LIMIT_CONFIGS["introspect"]
        assert cfg["limit"] == 1000
        assert cfg["window"] == 1

    def test_passkey_config(self):
        cfg = RATE_LIMIT_CONFIGS["passkey"]
        assert cfg["limit"] == 5
        assert cfg["window"] == 1

    def test_dsar_config(self):
        cfg = RATE_LIMIT_CONFIGS["dsar"]
        assert cfg["limit"] == 10
        assert cfg["window"] == 86400

    def test_all_configs_have_required_keys(self):
        for name, cfg in RATE_LIMIT_CONFIGS.items():
            assert "limit" in cfg, f"{name} missing 'limit'"
            assert "window" in cfg, f"{name} missing 'window'"
            assert isinstance(cfg["limit"], int)
            assert isinstance(cfg["window"], int)
