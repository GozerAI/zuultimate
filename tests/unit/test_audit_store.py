"""Unit tests for AI security audit store (DB persistence)."""

import pytest

from zuultimate.ai_security.audit_log import SecurityEvent, SecurityEventType
from zuultimate.ai_security.audit_store import persist_event, query_events


@pytest.fixture
async def audit_db(test_db):
    """Provide a DB manager with security_events table."""
    return test_db


async def test_persist_and_query(audit_db):
    event = SecurityEvent(
        event_type=SecurityEventType.SCAN,
        severity="info",
        agent_code="CTO",
        detail="test scan",
        threat_score=0.1,
    )
    await persist_event(audit_db, event)

    items, total = await query_events(audit_db)
    assert total == 1
    assert items[0]["event_type"] == "scan"
    assert items[0]["agent_code"] == "CTO"


async def test_query_by_event_type(audit_db):
    await persist_event(audit_db, SecurityEvent(
        event_type=SecurityEventType.SCAN, severity="info",
    ))
    await persist_event(audit_db, SecurityEvent(
        event_type=SecurityEventType.GUARD_BLOCK, severity="high",
    ))

    items, total = await query_events(audit_db, event_type=SecurityEventType.GUARD_BLOCK)
    assert total == 1
    assert items[0]["event_type"] == "guard_block"


async def test_query_by_severity(audit_db):
    await persist_event(audit_db, SecurityEvent(
        event_type=SecurityEventType.SCAN, severity="info",
    ))
    await persist_event(audit_db, SecurityEvent(
        event_type=SecurityEventType.THREAT_DETECTED, severity="critical",
    ))

    items, total = await query_events(audit_db, severity="critical")
    assert total == 1
    assert items[0]["severity"] == "critical"


async def test_query_pagination(audit_db):
    for i in range(5):
        await persist_event(audit_db, SecurityEvent(
            event_type=SecurityEventType.SCAN, severity="info", detail=f"event-{i}",
        ))

    items, total = await query_events(audit_db, limit=2, offset=0)
    assert total == 5
    assert len(items) == 2

    items2, _ = await query_events(audit_db, limit=2, offset=2)
    assert len(items2) == 2


async def test_query_empty(audit_db):
    items, total = await query_events(audit_db)
    assert total == 0
    assert items == []
