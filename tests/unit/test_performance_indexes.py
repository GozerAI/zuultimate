"""Tests for performance indexes on session and audit models."""

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from zuultimate.common.models import Base
from zuultimate.performance.indexes import verify_indexes


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://")
    import zuultimate.identity.models  # noqa: F401

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


class TestSessionIndexes:
    """Item #1: Composite indexes on session lookup columns."""

    async def test_composite_index_exists(self, engine):
        async with engine.connect() as conn:
            def _check(connection):
                insp = inspect(connection)
                indexes = insp.get_indexes("user_sessions")
                names = {idx["name"] for idx in indexes}
                return names
            names = await conn.run_sync(_check)
        assert "ix_user_sessions_user_active_expires" in names

    async def test_composite_index_columns(self, engine):
        async with engine.connect() as conn:
            def _check(connection):
                insp = inspect(connection)
                indexes = insp.get_indexes("user_sessions")
                for idx in indexes:
                    if idx["name"] == "ix_user_sessions_user_active_expires":
                        return idx["column_names"]
                return []
            cols = await conn.run_sync(_check)
        assert "user_id" in cols
        assert "expires_at" in cols
        assert "is_consumed" in cols


class TestPartialIndex:
    """Item #12: Partial index on active sessions only."""

    async def test_partial_index_exists(self, engine):
        async with engine.connect() as conn:
            def _check(connection):
                insp = inspect(connection)
                indexes = insp.get_indexes("user_sessions")
                names = {idx["name"] for idx in indexes}
                return names
            names = await conn.run_sync(_check)
        assert "ix_user_sessions_active_only" in names


class TestAuditIndex:
    """Composite index on auth_events for type + created_at."""

    async def test_audit_index_exists(self, engine):
        async with engine.connect() as conn:
            def _check(connection):
                insp = inspect(connection)
                indexes = insp.get_indexes("auth_events")
                names = {idx["name"] for idx in indexes}
                return names
            names = await conn.run_sync(_check)
        assert "ix_auth_events_type_created" in names


class TestVerifyIndexes:
    async def test_verify_all_present(self, engine):
        results = await verify_indexes(engine)
        assert results["ix_user_sessions_user_active_expires"] is True
        assert results["ix_user_sessions_active_only"] is True
        assert results["ix_auth_events_type_created"] is True

    async def test_verify_returns_dict(self, engine):
        results = await verify_indexes(engine)
        assert isinstance(results, dict)
        assert len(results) == 3
