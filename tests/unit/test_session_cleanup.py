"""Unit tests for session expiry cleanup task."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from zuultimate.common.tasks import SessionCleanupTask
from zuultimate.identity.models import User, UserSession


@pytest.fixture
def cleanup(test_db):
    return SessionCleanupTask(test_db, interval_seconds=60, max_age_hours=1)


async def _create_user(test_db, username="cleanupuser"):
    async with test_db.get_session("identity") as session:
        user = User(
            email=f"{username}@test.com",
            username=username,
            display_name=username,
        )
        session.add(user)
        await session.flush()
    return user.id


async def _create_session(test_db, user_id, age_hours=0):
    async with test_db.get_session("identity") as session:
        us = UserSession(
            user_id=user_id,
            access_token_hash=hashlib.sha256(f"access-{age_hours}".encode()).hexdigest(),
            refresh_token_hash=hashlib.sha256(f"refresh-{age_hours}".encode()).hexdigest(),
        )
        session.add(us)
        await session.flush()
        # Manually backdate created_at
        if age_hours > 0:
            us.created_at = datetime.utcnow() - timedelta(hours=age_hours)
    return us.id


async def test_cleanup_removes_expired(cleanup, test_db):
    user_id = await _create_user(test_db)
    await _create_session(test_db, user_id, age_hours=2)  # expired (>1h)
    await _create_session(test_db, user_id, age_hours=0)  # fresh

    removed = await cleanup.cleanup()
    assert removed == 1

    # One session should remain
    async with test_db.get_session("identity") as session:
        result = await session.execute(select(UserSession))
        remaining = result.scalars().all()
    assert len(remaining) == 1


async def test_cleanup_none_expired(cleanup, test_db):
    user_id = await _create_user(test_db, "freshuser")
    await _create_session(test_db, user_id, age_hours=0)

    removed = await cleanup.cleanup()
    assert removed == 0


async def test_cleanup_all_expired(cleanup, test_db):
    user_id = await _create_user(test_db, "allexpired")
    await _create_session(test_db, user_id, age_hours=5)
    await _create_session(test_db, user_id, age_hours=10)

    removed = await cleanup.cleanup()
    assert removed == 2


async def test_start_and_stop(test_db):
    task = SessionCleanupTask(test_db, interval_seconds=1, max_age_hours=1)
    await task.start()
    assert task._running is True
    await task.stop()
    assert task._running is False
