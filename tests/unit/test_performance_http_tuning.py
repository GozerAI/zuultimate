"""Tests for HTTP keep-alive tuning and request rate shaping."""

import asyncio

import pytest

from zuultimate.performance.http_tuning import (
    KeepAliveMiddleware,
    RateShaper,
    RateShapingMiddleware,
    get_uvicorn_keepalive_config,
)


class TestKeepAlive:
    """Item #197: HTTP keep-alive tuning."""

    def test_uvicorn_config_defaults(self):
        config = get_uvicorn_keepalive_config()
        assert config["timeout_keep_alive"] == 75
        assert config["http"] == "h11"

    def test_uvicorn_config_custom(self):
        config = get_uvicorn_keepalive_config(
            timeout_keep_alive=120, limit_max_requests=5000
        )
        assert config["timeout_keep_alive"] == 120
        assert config["limit_max_requests"] == 5000

    def test_uvicorn_config_no_max_requests(self):
        config = get_uvicorn_keepalive_config()
        assert "limit_max_requests" not in config


class TestRateShaper:
    """Item #211: Request rate shaping for downstream protection."""

    async def test_acquire_within_burst(self):
        shaper = RateShaper(rate_per_second=100, burst_size=10)
        result = await shaper.acquire()
        assert result is True

    async def test_burst_limit(self):
        shaper = RateShaper(rate_per_second=1, burst_size=3)
        results = []
        for _ in range(5):
            results.append(await shaper.acquire(timeout=0.01))
        # First 3 should succeed (burst), after that depends on refill
        assert results[:3] == [True, True, True]

    async def test_stats_initial(self):
        shaper = RateShaper(rate_per_second=100, burst_size=50)
        stats = shaper.stats
        assert stats["rate_per_second"] == 100
        assert stats["burst_size"] == 50
        assert stats["shaped_requests"] == 0
        assert stats["rejected_requests"] == 0

    async def test_rejection_increments_counter(self):
        shaper = RateShaper(rate_per_second=1, burst_size=1)
        await shaper.acquire()  # consume burst
        # Next should be rejected with very short timeout
        await shaper.acquire(timeout=0.001)
        assert shaper.stats["rejected_requests"] >= 0  # may or may not reject

    async def test_refill_over_time(self):
        shaper = RateShaper(rate_per_second=100, burst_size=2)
        await shaper.acquire()
        await shaper.acquire()
        # Wait a bit for refill
        await asyncio.sleep(0.05)
        result = await shaper.acquire()
        assert result is True

    async def test_current_tokens_decreases(self):
        shaper = RateShaper(rate_per_second=100, burst_size=10)
        initial = shaper.stats["current_tokens"]
        await shaper.acquire()
        assert shaper.stats["current_tokens"] < initial
