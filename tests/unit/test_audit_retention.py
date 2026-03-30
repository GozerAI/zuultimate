"""Unit tests for audit log retention service."""

from datetime import datetime, timedelta

import pytest

from zuultimate.ai_security.models import SecurityEventModel
from zuultimate.ai_security.retention import AuditRetentionService


@pytest.fixture
def svc(test_db):
    return AuditRetentionService(test_db, retention_days=30)


async def _insert_event(test_db, age_days=0, event_type="scan", severity="low"):
    async with test_db.get_session("audit") as session:
        event = SecurityEventModel(
            event_type=event_type,
            severity=severity,
            agent_code="CTO",
            detail="test event",
            threat_score=0.1,
        )
        session.add(event)
        await session.flush()
        if age_days > 0:
            event.created_at = datetime.utcnow() - timedelta(days=age_days)
    return event.id


async def test_stats_empty(svc):
    stats = await svc.get_stats()
    assert stats["total_events"] == 0
    assert stats["expired_events"] == 0
    assert stats["retention_days"] == 30


async def test_stats_with_events(svc, test_db):
    await _insert_event(test_db, age_days=0)   # fresh
    await _insert_event(test_db, age_days=60)  # expired
    await _insert_event(test_db, age_days=90)  # expired

    stats = await svc.get_stats()
    assert stats["total_events"] == 3
    assert stats["expired_events"] == 2


async def test_archive_expired(svc, test_db):
    await _insert_event(test_db, age_days=60)
    await _insert_event(test_db, age_days=0)

    result = await svc.archive_expired()
    assert result["archived_count"] == 1
    assert len(result["events"]) == 1
    assert result["archive_json"] is not None


async def test_archive_empty(svc):
    result = await svc.archive_expired()
    assert result["archived_count"] == 0


async def test_purge_expired(svc, test_db):
    await _insert_event(test_db, age_days=60)
    await _insert_event(test_db, age_days=60)
    await _insert_event(test_db, age_days=0)

    result = await svc.purge_expired()
    assert result["purged"] == 2

    # Only 1 should remain
    stats = await svc.get_stats()
    assert stats["total_events"] == 1


async def test_purge_nothing_expired(svc, test_db):
    await _insert_event(test_db, age_days=0)
    result = await svc.purge_expired()
    assert result["purged"] == 0
