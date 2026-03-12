"""Tests for Phase 1.3 auth edge controls -- event emitter and progressive lockout."""

import hashlib
import time

import pytest

from zuultimate.common.redis import RedisManager
from zuultimate.identity.auth_events import AuthEventEmitter
from zuultimate.identity.lockout import LockoutService
from zuultimate.identity.models import AuthEvent


# -- fixtures --


@pytest.fixture
async def redis():
    mgr = RedisManager("redis://localhost:9999")
    await mgr.connect()  # will fail and fallback to in-memory
    yield mgr
    await mgr.close()


@pytest.fixture
def emitter(test_db):
    return AuthEventEmitter(test_db)


@pytest.fixture
def lockout(redis):
    return LockoutService(redis)


# -- AuthEventEmitter tests --


@pytest.mark.asyncio
async def test_auth_event_emitter_records_event(test_db, emitter):
    """Verify that emit() writes an event row to the database."""
    event = await emitter.emit(
        event_type="auth_success",
        ip="192.168.1.1",
        user_agent="Mozilla/5.0",
        username="alice",
    )
    assert event.id is not None
    assert event.event_type == "auth_success"

    # Read back from DB to confirm persistence
    from sqlalchemy import select

    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(AuthEvent).where(AuthEvent.id == event.id)
        )
        row = result.scalar_one_or_none()
    assert row is not None
    assert row.event_type == "auth_success"


@pytest.mark.asyncio
async def test_auth_event_hashes_ip(test_db, emitter):
    """Verify that the raw IP address is never stored -- only its hash."""
    raw_ip = "10.0.0.42"
    event = await emitter.emit(
        event_type="auth_failure",
        ip=raw_ip,
        username="bob",
    )
    expected_hash = hashlib.sha256(raw_ip.encode()).hexdigest()
    assert event.ip_hash == expected_hash
    assert raw_ip not in event.ip_hash
    assert raw_ip not in (event.metadata_json or "")


# -- LockoutService tests --


@pytest.mark.asyncio
async def test_lockout_allows_under_threshold(lockout):
    """Four failures should not trigger a lockout."""
    for _ in range(4):
        await lockout.record_failure("1.2.3.4", "user1")
    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user1")
    assert is_locked is False
    assert remaining == 0


@pytest.mark.asyncio
async def test_lockout_triggers_at_5_failures(lockout):
    """Five failures should trigger a 30-second lockout."""
    for _ in range(5):
        await lockout.record_failure("1.2.3.4", "user2")
    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user2")
    assert is_locked is True
    assert remaining > 0
    assert remaining <= 30


@pytest.mark.asyncio
async def test_lockout_escalates_at_10(lockout):
    """Ten failures should escalate to a 5-minute lockout."""
    for _ in range(10):
        await lockout.record_failure("1.2.3.4", "user3")
    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user3")
    assert is_locked is True
    assert remaining > 30


@pytest.mark.asyncio
async def test_lockout_escalates_at_20(lockout):
    """Twenty failures should escalate to a 15-minute lockout."""
    for _ in range(20):
        await lockout.record_failure("1.2.3.4", "user4")
    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user4")
    assert is_locked is True
    assert remaining > 300


@pytest.mark.asyncio
async def test_lockout_success_resets(lockout):
    """A successful auth should clear lockout state and counters."""
    for _ in range(5):
        await lockout.record_failure("1.2.3.4", "user5")
    is_locked, _ = await lockout.check_lockout("1.2.3.4", "user5")
    assert is_locked is True

    await lockout.record_success("1.2.3.4", "user5")
    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user5")
    assert is_locked is False
    assert remaining == 0


@pytest.mark.asyncio
async def test_lockout_cooldown_expires(lockout):
    """After the TTL expires the lockout should clear automatically."""
    # Trigger a lockout at the 5-failure threshold (30s cooldown)
    for _ in range(5):
        await lockout.record_failure("1.2.3.4", "user6")
    is_locked, _ = await lockout.check_lockout("1.2.3.4", "user6")
    assert is_locked is True

    # Manually expire the lockout keys by rewinding their TTL
    ip_hash = hashlib.sha256("1.2.3.4".encode()).hexdigest()
    user_hash = hashlib.sha256("user6".encode()).hexdigest()
    past = time.time() - 1
    lockout._redis._mem_expiry[f"lockout:ip:{ip_hash}"] = past
    lockout._redis._mem_expiry[f"lockout:user:{user_hash}"] = past

    is_locked, remaining = await lockout.check_lockout("1.2.3.4", "user6")
    assert is_locked is False
    assert remaining == 0
