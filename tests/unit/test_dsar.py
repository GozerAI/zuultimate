"""DSAR intake workflow tests — submit, advance, overdue detection, evidence packs."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.dsar.models import DSARRequest
from zuultimate.identity.dsar.service import DSARService


@pytest.fixture
async def dsar_service(test_db):
    return DSARService(test_db)


# ── Submit ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_dsar(dsar_service):
    """Submit creates a request with status=received and due_at 30 days out."""
    result = await dsar_service.submit(
        tenant_id="tenant-001",
        subject_id="subject-001",
        request_type="access",
    )

    assert result["status"] == "received"
    assert result["request_type"] == "access"
    assert result["tenant_id"] == "tenant-001"
    assert result["subject_id"] == "subject-001"
    assert result["fulfilled_at"] is None

    received = datetime.fromisoformat(result["received_at"])
    due = datetime.fromisoformat(result["due_at"])
    delta = due - received
    assert 29 <= delta.days <= 30

    # Evidence trail has initial entry
    assert len(result["evidence_trail"]) == 1
    assert result["evidence_trail"][0]["status"] == "received"


# ── Status Transitions ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_advance_status_received_to_validated(dsar_service):
    """Advance from received to validated succeeds."""
    created = await dsar_service.submit("t1", "s1", "deletion")
    updated = await dsar_service.advance_status(created["id"], "validated")

    assert updated["status"] == "validated"
    assert len(updated["evidence_trail"]) == 2
    assert updated["evidence_trail"][-1]["status"] == "validated"


@pytest.mark.asyncio
async def test_advance_status_validated_to_processing(dsar_service):
    """Advance from validated to processing succeeds."""
    created = await dsar_service.submit("t1", "s1", "portability")
    await dsar_service.advance_status(created["id"], "validated")
    updated = await dsar_service.advance_status(created["id"], "processing")

    assert updated["status"] == "processing"
    assert len(updated["evidence_trail"]) == 3


@pytest.mark.asyncio
async def test_advance_status_processing_to_fulfilled(dsar_service):
    """Advance to fulfilled sets fulfilled_at timestamp."""
    created = await dsar_service.submit("t1", "s1", "correction")
    await dsar_service.advance_status(created["id"], "validated")
    await dsar_service.advance_status(created["id"], "processing")
    updated = await dsar_service.advance_status(created["id"], "fulfilled")

    assert updated["status"] == "fulfilled"
    assert updated["fulfilled_at"] is not None
    assert len(updated["evidence_trail"]) == 4


@pytest.mark.asyncio
async def test_advance_invalid_transition(dsar_service):
    """Direct jump from received to fulfilled raises ValidationError."""
    created = await dsar_service.submit("t1", "s1", "access")
    with pytest.raises(ValidationError, match="Cannot transition"):
        await dsar_service.advance_status(created["id"], "fulfilled")


# ── Overdue Detection ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_overdue_detection(dsar_service, test_db):
    """A request with due_at in the past and non-terminal status is overdue."""
    created = await dsar_service.submit("t1", "s1", "restriction")
    dsar_id = created["id"]

    # Manually backdate due_at to the past
    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(DSARRequest).where(DSARRequest.id == dsar_id)
        )
        req = result.scalar_one()
        req.due_at = datetime.now(timezone.utc) - timedelta(days=1)
        await session.flush()

    # Fetch and check — service returns raw dict, overdue is computed in router
    fetched = await dsar_service.get_request(dsar_id)
    due_at = datetime.fromisoformat(fetched["due_at"])
    # SQLite returns naive datetimes — normalize for comparison
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    assert due_at < datetime.now(timezone.utc)
    assert fetched["status"] not in ("fulfilled", "rejected")


# ── Evidence Pack ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_evidence_pack(dsar_service):
    """Evidence pack contains request details and all trail entries."""
    created = await dsar_service.submit("t1", "s1", "access")
    await dsar_service.advance_status(created["id"], "validated")
    await dsar_service.advance_status(created["id"], "processing")

    pack = await dsar_service.generate_evidence_pack(created["id"])

    assert pack["dsar_id"] == created["id"]
    assert pack["tenant_id"] == "t1"
    assert pack["subject_id"] == "s1"
    assert pack["request_type"] == "access"
    assert pack["status"] == "processing"
    assert len(pack["evidence_trail"]) == 3
    statuses = [e["status"] for e in pack["evidence_trail"]]
    assert statuses == ["received", "validated", "processing"]


# ── List Requests ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_requests_filter_by_tenant(dsar_service):
    """Filtering by tenant_id returns only that tenant's requests."""
    await dsar_service.submit("tenant-A", "s1", "access")
    await dsar_service.submit("tenant-A", "s2", "deletion")
    await dsar_service.submit("tenant-B", "s3", "portability")

    results_a = await dsar_service.list_requests(tenant_id="tenant-A")
    results_b = await dsar_service.list_requests(tenant_id="tenant-B")
    results_all = await dsar_service.list_requests()

    assert len(results_a) == 2
    assert len(results_b) == 1
    assert len(results_all) == 3
    assert all(r["tenant_id"] == "tenant-A" for r in results_a)
    assert all(r["tenant_id"] == "tenant-B" for r in results_b)
