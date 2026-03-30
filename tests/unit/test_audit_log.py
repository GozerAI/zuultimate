"""Tests for zuultimate.ai_security.audit_log -- append-only security event log."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import List

from zuultimate.ai_security.audit_log import (
    SecurityAuditLog,
    SecurityEvent,
    SecurityEventType,
)
from zuultimate.ai_security.patterns import Severity


# ---------------------------------------------------------------------------
# Helpers -- lightweight stub for ScanResult to avoid circular coupling
# ---------------------------------------------------------------------------

@dataclass
class _FakeScanResult:
    is_threat: bool
    threat_score: float
    detections: List = field(default_factory=list)
    max_severity: Severity | None = None


@dataclass
class _FakeGuardDecision:
    allowed: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Basic record / count
# ---------------------------------------------------------------------------

def test_record_and_count():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN))
    assert log.count == 1


def test_maxlen_enforced():
    log = SecurityAuditLog(maxlen=5)
    for _ in range(10):
        log.record(SecurityEvent(event_type=SecurityEventType.SCAN))
    assert log.count == 5


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------

def test_query_by_event_type():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN))
    log.record(SecurityEvent(event_type=SecurityEventType.GUARD_BLOCK))
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN))

    results = log.query(event_type=SecurityEventType.SCAN)
    assert len(results) == 2
    assert all(e.event_type == SecurityEventType.SCAN for e in results)


def test_query_by_severity():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN, severity="info"))
    log.record(SecurityEvent(event_type=SecurityEventType.THREAT_DETECTED, severity="critical"))
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN, severity="info"))

    results = log.query(severity="critical")
    assert len(results) == 1
    assert results[0].severity == "critical"


def test_query_by_agent_code():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN, agent_code="CTO"))
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN, agent_code="CFO"))

    results = log.query(agent_code="CTO")
    assert len(results) == 1
    assert results[0].agent_code == "CTO"


def test_query_limit():
    log = SecurityAuditLog()
    for i in range(20):
        log.record(SecurityEvent(event_type=SecurityEventType.SCAN, detail=str(i)))

    results = log.query(limit=5)
    assert len(results) == 5


# ---------------------------------------------------------------------------
# Export / clear
# ---------------------------------------------------------------------------

def test_export_json():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN, agent_code="CTO"))
    raw = log.export_json()
    data = json.loads(raw)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["agent_code"] == "CTO"


def test_clear():
    log = SecurityAuditLog()
    log.record(SecurityEvent(event_type=SecurityEventType.SCAN))
    assert log.count == 1
    log.clear()
    assert log.count == 0


# ---------------------------------------------------------------------------
# record_scan helper
# ---------------------------------------------------------------------------

def test_record_scan_threat():
    log = SecurityAuditLog()
    scan = _FakeScanResult(
        is_threat=True,
        threat_score=0.9,
        detections=["d1"],
        max_severity=Severity.CRITICAL,
    )
    log.record_scan(scan, agent_code="CTO", text_preview="evil input")
    assert log.count == 1
    events = log.query(event_type=SecurityEventType.THREAT_DETECTED)
    assert len(events) == 1
    assert events[0].severity == "critical"


def test_record_scan_clean():
    log = SecurityAuditLog()
    scan = _FakeScanResult(is_threat=False, threat_score=0.0, max_severity=None)
    log.record_scan(scan, agent_code="CTO", text_preview="safe input")
    events = log.query(event_type=SecurityEventType.SCAN)
    assert len(events) == 1


# ---------------------------------------------------------------------------
# record_guard_decision helper
# ---------------------------------------------------------------------------

def test_record_guard_decision():
    log = SecurityAuditLog()

    allowed = _FakeGuardDecision(allowed=True, reason="")
    log.record_guard_decision(allowed, tool_name="tool_a", agent_code="CTO")
    events_ok = log.query(event_type=SecurityEventType.GUARD_CHECK)
    assert len(events_ok) == 1

    blocked = _FakeGuardDecision(allowed=False, reason="injection detected")
    log.record_guard_decision(blocked, tool_name="tool_b", agent_code="CFO")
    events_block = log.query(event_type=SecurityEventType.GUARD_BLOCK)
    assert len(events_block) == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_thread_safety():
    log = SecurityAuditLog(maxlen=2000)
    barrier = threading.Barrier(10)

    def _writer():
        barrier.wait()
        for _ in range(100):
            log.record(SecurityEvent(event_type=SecurityEventType.SCAN))

    threads = [threading.Thread(target=_writer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert log.count == 1000
