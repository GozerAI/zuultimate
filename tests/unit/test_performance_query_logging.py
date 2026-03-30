"""Tests for database query logging with slow query alerts."""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from zuultimate.common.models import Base
from zuultimate.performance.query_logging import QueryLogger, SlowQueryRecord


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


class TestQueryLogger:
    """Item #35: Database query logging with slow query alerts."""

    async def test_attach_and_query(self, engine):
        logger = QueryLogger(slow_threshold_ms=0.0001)
        logger.attach(engine, db_key="identity")

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert logger.stats["total_queries"] >= 1

    async def test_slow_query_captured(self, engine):
        logger = QueryLogger(slow_threshold_ms=0.0001)
        logger.attach(engine, db_key="identity")

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert logger.stats["slow_queries"] >= 1
        records = logger.recent_slow_queries
        assert len(records) >= 1
        assert records[0]["db_key"] == "identity"
        assert records[0]["elapsed_ms"] >= 0

    async def test_normal_query_not_captured(self, engine):
        logger = QueryLogger(slow_threshold_ms=999999)
        logger.attach(engine, db_key="identity")

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert logger.stats["slow_queries"] == 0
        assert logger.recent_slow_queries == []

    async def test_ring_buffer_limit(self, engine):
        logger = QueryLogger(slow_threshold_ms=0.0001, ring_size=5)
        logger.attach(engine, db_key="test")

        async with engine.connect() as conn:
            for _ in range(10):
                await conn.execute(text("SELECT 1"))

        assert len(logger.recent_slow_queries) <= 5

    async def test_alert_callback(self, engine):
        alerts = []
        logger = QueryLogger(
            slow_threshold_ms=0.0001,
            alert_callback=lambda r: alerts.append(r),
        )
        logger.attach(engine, db_key="test")

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        assert len(alerts) >= 1
        assert isinstance(alerts[0], SlowQueryRecord)

    async def test_attach_all(self, engine):
        logger = QueryLogger()
        logger.attach_all({"identity": engine})
        assert logger.stats["total_queries"] == 0

    async def test_stats_structure(self, engine):
        logger = QueryLogger()
        stats = logger.stats
        assert "total_queries" in stats
        assert "slow_queries" in stats
        assert "buffered" in stats
