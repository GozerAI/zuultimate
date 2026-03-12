"""Unit tests for data retention enforcement."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from zuultimate.identity.consent.models import ConsentRecord
from zuultimate.identity.models import AuthEvent, Tenant
from zuultimate.identity.retention import DataRetentionJob


@pytest.fixture
async def test_db_with_consent(test_settings):
    """Extend test_db to also create consent tables."""
    import zuultimate.identity.models  # noqa: F401
    import zuultimate.identity.phase2_models  # noqa: F401
    import zuultimate.identity.consent.models  # noqa: F401
    import zuultimate.access.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.pos.models  # noqa: F401
    import zuultimate.crm.models  # noqa: F401
    import zuultimate.backup_resilience.models  # noqa: F401
    import zuultimate.ai_security.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401
    import zuultimate.common.idempotency  # noqa: F401

    from zuultimate.common.database import DatabaseManager

    db = DatabaseManager(test_settings)
    await db.init()
    await db.create_all()
    yield db
    await db.close_all()


@pytest.fixture
def retention_job(test_db_with_consent):
    return DataRetentionJob(test_db_with_consent)


async def _create_tenant(db, retention_days=365):
    """Create a tenant with specified retention days."""
    tenant = Tenant(
        name="Test Corp",
        slug=f"test-corp-{retention_days}",
        default_retention_days=retention_days,
    )
    async with db.get_session("identity") as session:
        session.add(tenant)
        await session.flush()
        tid = tenant.id
    return tid


async def _create_consent_record(db, tenant_id, age_days=0):
    """Create a consent record, optionally back-dated."""
    now = datetime.now(timezone.utc)
    record = ConsentRecord(
        tenant_id=tenant_id,
        subject_id="user-1",
        purpose="analytics",
        granted=True,
        granted_at=now,
    )
    async with db.get_session("identity") as session:
        session.add(record)
        await session.flush()
        if age_days > 0:
            record.created_at = now - timedelta(days=age_days)
        rid = record.id
    return rid


async def _create_auth_event(db, age_days=0):
    """Create an auth event, optionally back-dated."""
    now = datetime.now(timezone.utc)
    event = AuthEvent(
        event_type="login",
        ip_hash="abc123",
        user_agent_hash="ua123",
        metadata_json="{}",
    )
    async with db.get_session("identity") as session:
        session.add(event)
        await session.flush()
        if age_days > 0:
            event.created_at = now - timedelta(days=age_days)
        eid = event.id
    return eid


async def test_dry_run_emits_audit_but_no_delete(retention_job, test_db_with_consent):
    """Dry run emits audit events but leaves records intact."""
    db = test_db_with_consent
    tid = await _create_tenant(db, retention_days=0)
    rid = await _create_consent_record(db, tid, age_days=1)

    result = await retention_job.scan(dry_run=True)

    assert result["purged"] is False
    assert result["expired_records_found"] >= 1

    # Record still exists
    async with db.get_session("identity") as session:
        row = await session.get(ConsentRecord, rid)
        assert row is not None

    # Audit event was emitted
    async with db.get_session("identity") as session:
        stmt = select(AuthEvent).where(AuthEvent.event_type == "retention_scan")
        rows = (await session.execute(stmt)).scalars().all()
        assert len(rows) >= 1


async def test_wet_run_purges_expired(retention_job, test_db_with_consent):
    """Wet run deletes expired records."""
    db = test_db_with_consent
    tid = await _create_tenant(db, retention_days=0)
    rid = await _create_consent_record(db, tid, age_days=1)

    result = await retention_job.scan(dry_run=False)

    assert result["purged"] is True
    assert result["expired_records_found"] >= 1

    # Record was deleted
    async with db.get_session("identity") as session:
        row = await session.get(ConsentRecord, rid)
        assert row is None


async def test_respects_tenant_retention_days(retention_job, test_db_with_consent):
    """Records within the retention window are not flagged as expired."""
    db = test_db_with_consent
    tid = await _create_tenant(db, retention_days=365)
    await _create_consent_record(db, tid, age_days=0)

    result = await retention_job.scan(dry_run=True)

    # No consent records should be expired (only auth events without tenant scoping may appear)
    consent_expired = [d for d in result["details"] if d["table"] == "consent_records"]
    assert len(consent_expired) == 0


async def test_scan_returns_summary(retention_job, test_db_with_consent):
    """Scan returns a summary dict with the correct shape and counts."""
    db = test_db_with_consent
    tid = await _create_tenant(db, retention_days=0)
    await _create_consent_record(db, tid, age_days=5)
    await _create_consent_record(db, tid, age_days=10)
    await _create_auth_event(db, age_days=5)

    result = await retention_job.scan(dry_run=True)

    assert "tenant_count" in result
    assert "expired_records_found" in result
    assert "purged" in result
    assert "details" in result
    assert result["tenant_count"] >= 1
    assert result["expired_records_found"] >= 2
    assert isinstance(result["details"], list)
    for detail in result["details"]:
        assert "table" in detail
        assert "record_id" in detail
        assert "tenant_id" in detail
        assert "age_days" in detail
