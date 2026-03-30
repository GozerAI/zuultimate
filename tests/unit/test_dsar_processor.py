"""Unit tests for automated DSAR processing (item 909)."""

import pytest
from datetime import datetime, timedelta, timezone

from zuultimate.compliance.dsar_processor import (
    DSAREntry,
    DSARProcessor,
    DSARStatus,
    DSARType,
)


class TestDSARProcessor:
    @pytest.fixture
    def processor(self):
        return DSARProcessor(sla_days=30)

    def test_submit_creates_request(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        assert entry.status == DSARStatus.RECEIVED
        assert entry.tenant_id == "t1"
        assert entry.subject_id == "u1"
        assert entry.request_type == DSARType.ACCESS
        assert len(entry.evidence_trail) == 1

    def test_submit_sets_due_date(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        delta = entry.due_at - entry.received_at
        assert 29 <= delta.days <= 30

    def test_advance_received_to_validated(self, processor):
        entry = processor.submit("t1", "u1", DSARType.DELETION)
        updated = processor.advance(entry.request_id, DSARStatus.VALIDATED)
        assert updated.status == DSARStatus.VALIDATED
        assert len(updated.evidence_trail) == 2

    def test_advance_to_processing(self, processor):
        entry = processor.submit("t1", "u1", DSARType.PORTABILITY)
        processor.advance(entry.request_id, DSARStatus.VALIDATED)
        updated = processor.advance(entry.request_id, DSARStatus.PROCESSING)
        assert updated.status == DSARStatus.PROCESSING

    def test_advance_to_fulfilled(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        processor.advance(entry.request_id, DSARStatus.VALIDATED)
        processor.advance(entry.request_id, DSARStatus.PROCESSING)
        updated = processor.advance(entry.request_id, DSARStatus.FULFILLED)
        assert updated.status == DSARStatus.FULFILLED
        assert updated.fulfilled_at is not None
        assert updated.is_terminal

    def test_advance_to_rejected(self, processor):
        entry = processor.submit("t1", "u1", DSARType.CORRECTION)
        updated = processor.advance(entry.request_id, DSARStatus.REJECTED, "Invalid request")
        assert updated.status == DSARStatus.REJECTED
        assert updated.rejected_at is not None
        assert updated.rejection_reason == "Invalid request"

    def test_invalid_transition_raises(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        with pytest.raises(ValueError, match="Cannot transition"):
            processor.advance(entry.request_id, DSARStatus.FULFILLED)

    def test_advance_nonexistent_raises(self, processor):
        with pytest.raises(KeyError):
            processor.advance("nonexistent", DSARStatus.VALIDATED)

    def test_get_request(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        fetched = processor.get_request(entry.request_id)
        assert fetched is not None
        assert fetched.request_id == entry.request_id

    def test_get_nonexistent(self, processor):
        assert processor.get_request("nope") is None

    def test_list_requests(self, processor):
        processor.submit("t1", "u1", DSARType.ACCESS)
        processor.submit("t1", "u2", DSARType.DELETION)
        processor.submit("t2", "u3", DSARType.ACCESS)
        assert len(processor.list_requests()) == 3
        assert len(processor.list_requests(tenant_id="t1")) == 2
        assert len(processor.list_requests(tenant_id="t2")) == 1

    def test_list_requests_by_status(self, processor):
        e1 = processor.submit("t1", "u1", DSARType.ACCESS)
        processor.submit("t1", "u2", DSARType.DELETION)
        processor.advance(e1.request_id, DSARStatus.VALIDATED)
        validated = processor.list_requests(status=DSARStatus.VALIDATED)
        assert len(validated) == 1

    def test_overdue_detection(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        # Not overdue yet
        assert not entry.is_overdue
        # Force overdue
        entry.due_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert entry.is_overdue
        overdue = processor.get_overdue_requests()
        assert len(overdue) == 1

    def test_fulfilled_not_overdue(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        processor.advance(entry.request_id, DSARStatus.VALIDATED)
        processor.advance(entry.request_id, DSARStatus.PROCESSING)
        processor.advance(entry.request_id, DSARStatus.FULFILLED)
        entry.due_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert not entry.is_overdue

    def test_days_remaining(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        assert entry.days_remaining > 0

    def test_sla_summary_empty(self, processor):
        s = processor.get_sla_summary()
        assert s["total"] == 0
        assert s["sla_compliance_rate"] == 1.0

    def test_sla_summary_with_data(self, processor):
        e1 = processor.submit("t1", "u1", DSARType.ACCESS)
        processor.advance(e1.request_id, DSARStatus.VALIDATED)
        processor.advance(e1.request_id, DSARStatus.PROCESSING)
        processor.advance(e1.request_id, DSARStatus.FULFILLED)
        s = processor.get_sla_summary("t1")
        assert s["total"] == 1
        assert s["fulfilled"] == 1
        assert s["sla_compliance_rate"] == 1.0

    def test_metadata(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS, metadata={"ip": "1.2.3.4"})
        assert entry.metadata == {"ip": "1.2.3.4"}

    def test_evidence_trail_grows(self, processor):
        entry = processor.submit("t1", "u1", DSARType.ACCESS)
        processor.advance(entry.request_id, DSARStatus.VALIDATED, "ID verified")
        processor.advance(entry.request_id, DSARStatus.PROCESSING, "Gathering data")
        processor.advance(entry.request_id, DSARStatus.FULFILLED, "Sent to user")
        assert len(entry.evidence_trail) == 4
        statuses = [e["status"] for e in entry.evidence_trail]
        assert statuses == ["received", "validated", "processing", "fulfilled"]
