"""Tests for connection pool warm-up and query timeout enforcement."""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from zuultimate.common.models import Base
from zuultimate.performance.connection_pool import (
    QueryTimeoutEnforcer,
    warm_all_pools,
    warm_pool,
)


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


class TestPoolWarmup:
    """Item #2: Connection pool warm-up on startup."""

    async def test_warm_pool_returns_count(self, engine):
        count = await warm_pool(engine, pool_size=2)
        assert count == 2

    async def test_warm_pool_zero(self, engine):
        count = await warm_pool(engine, pool_size=0)
        assert count == 0

    async def test_warm_all_pools(self, engine):
        engines = {"identity": engine, "session": engine}
        results = await warm_all_pools(engines, pool_size=1)
        assert results["identity"] == 1
        assert results["session"] == 1


class TestQueryTimeoutEnforcer:
    """Item #22: Database query timeout enforcement."""

    async def test_attach_does_not_raise(self, engine):
        enforcer = QueryTimeoutEnforcer(warn_threshold_ms=1.0)
        enforcer.attach(engine)
        # Should not raise

    async def test_records_query_stats(self, engine):
        enforcer = QueryTimeoutEnforcer(warn_threshold_ms=0.0001)
        enforcer.attach(engine)

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert enforcer.stats["total_queries"] >= 1

    async def test_slow_query_logged(self, engine):
        # With a very low threshold every query is "slow"
        enforcer = QueryTimeoutEnforcer(
            warn_threshold_ms=0.0001, abort_threshold_ms=999999
        )
        enforcer.attach(engine)

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert enforcer.stats["slow_count"] >= 1
        assert len(enforcer.stats["recent_slow"]) >= 1

    async def test_normal_query_not_flagged(self, engine):
        enforcer = QueryTimeoutEnforcer(
            warn_threshold_ms=999999, abort_threshold_ms=999999
        )
        enforcer.attach(engine)

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert enforcer.stats["slow_count"] == 0

    async def test_attach_all(self, engine):
        enforcer = QueryTimeoutEnforcer()
        enforcer.attach_all({"identity": engine})
        # Verify we can still query
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
