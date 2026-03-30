"""Unit tests for compliance report generation."""

import pytest

from zuultimate.ai_security.audit_log import SecurityEvent, SecurityEventType
from zuultimate.ai_security.audit_store import persist_event
from zuultimate.ai_security.compliance import ComplianceReporter


@pytest.fixture
async def reporter(test_db):
    return ComplianceReporter(test_db)


async def test_empty_report(reporter):
    report = await reporter.generate_report()
    assert report["summary"]["total_events"] == 0
    assert report["by_type"] == {}
    assert report["threat_analysis"]["total_threats"] == 0


async def test_report_with_events(reporter, test_db):
    await persist_event(test_db, SecurityEvent(
        event_type=SecurityEventType.SCAN, severity="info",
        agent_code="CTO", threat_score=0.1,
    ))
    await persist_event(test_db, SecurityEvent(
        event_type=SecurityEventType.THREAT_DETECTED, severity="high",
        agent_code="CTO", threat_score=0.8,
    ))
    await persist_event(test_db, SecurityEvent(
        event_type=SecurityEventType.GUARD_BLOCK, severity="critical",
        agent_code="CFO", threat_score=0.9,
    ))

    report = await reporter.generate_report()
    assert report["summary"]["total_events"] == 3
    assert report["summary"]["unique_agents"] == 2
    assert report["by_type"]["scan"] == 1
    assert report["by_type"]["threat_detected"] == 1
    assert report["by_severity"]["high"] == 1
    assert report["threat_analysis"]["total_threats"] == 2
    assert report["threat_analysis"]["avg_threat_score"] > 0
    assert report["policy_violations"] == 1


async def test_report_agent_activity(reporter, test_db):
    for _ in range(3):
        await persist_event(test_db, SecurityEvent(
            event_type=SecurityEventType.SCAN, severity="info", agent_code="CTO",
        ))
    await persist_event(test_db, SecurityEvent(
        event_type=SecurityEventType.SCAN, severity="info", agent_code="CFO",
    ))

    report = await reporter.generate_report()
    assert report["agent_activity"]["CTO"] == 3
    assert report["agent_activity"]["CFO"] == 1
