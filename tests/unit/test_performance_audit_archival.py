"""Tests for audit log archival to cold storage."""

import json
from datetime import datetime, timezone, timedelta

import pytest

from zuultimate.common.database import DatabaseManager
from zuultimate.common.models import Base
from zuultimate.performance.audit_archival import AuditArchiver, LocalJSONLBackend


@pytest.fixture
async def db():
    from zuultimate.common.config import ZuulSettings

    settings = ZuulSettings(
        identity_db_url="sqlite+aiosqlite://",
        credential_db_url="sqlite+aiosqlite://",
        session_db_url="sqlite+aiosqlite://",
        transaction_db_url="sqlite+aiosqlite://",
        audit_db_url="sqlite+aiosqlite://",
        crm_db_url="sqlite+aiosqlite://",
        secret_key="test-key",
    )
    import zuultimate.identity.models  # noqa: F401

    db_mgr = DatabaseManager(settings)
    await db_mgr.init()
    await db_mgr.create_all()
    yield db_mgr
    await db_mgr.close_all()


class _InMemoryBackend:
    """Test backend that stores events in memory."""

    def __init__(self):
        self.batches: list[tuple[list[dict], str]] = []

    async def write_batch(self, events, archive_key):
        self.batches.append((events, archive_key))
        return f"mem://{archive_key}"


class TestAuditArchiver:
    """Item #28: Audit log archival to cold storage."""

    async def test_archive_empty_db(self, db):
        backend = _InMemoryBackend()
        archiver = AuditArchiver(db, backend=backend, retention_days=0)
        result = await archiver.archive()
        assert result["archived"] == 0
        assert result["eligible"] == 0

    async def test_archive_old_events(self, db):
        from zuultimate.identity.models import AuthEvent

        # Insert old events
        old_time = datetime.now(timezone.utc) - timedelta(days=100)
        async with db.get_session("identity") as session:
            for i in range(5):
                session.add(AuthEvent(
                    event_type="login",
                    ip_hash=f"hash{i}",
                    user_agent_hash="ua",
                    created_at=old_time,
                ))

        backend = _InMemoryBackend()
        archiver = AuditArchiver(db, backend=backend, retention_days=30)
        result = await archiver.archive()

        assert result["archived"] == 5
        assert result["deleted"] == 5
        assert len(backend.batches) == 1
        assert len(backend.batches[0][0]) == 5

    async def test_archive_respects_retention(self, db):
        from zuultimate.identity.models import AuthEvent

        # Insert recent events (should NOT be archived)
        async with db.get_session("identity") as session:
            for i in range(3):
                session.add(AuthEvent(
                    event_type="login",
                    ip_hash=f"hash{i}",
                    user_agent_hash="ua",
                    created_at=datetime.now(timezone.utc),
                ))

        backend = _InMemoryBackend()
        archiver = AuditArchiver(db, backend=backend, retention_days=30)
        result = await archiver.archive()

        assert result["archived"] == 0
        assert result["eligible"] == 0

    async def test_archive_batch_size(self, db):
        from zuultimate.identity.models import AuthEvent

        old_time = datetime.now(timezone.utc) - timedelta(days=100)
        async with db.get_session("identity") as session:
            for i in range(10):
                session.add(AuthEvent(
                    event_type="login",
                    ip_hash=f"hash{i}",
                    user_agent_hash="ua",
                    created_at=old_time,
                ))

        backend = _InMemoryBackend()
        archiver = AuditArchiver(db, backend=backend, retention_days=30, batch_size=3)
        result = await archiver.archive()

        assert result["archived"] == 3  # Only processes batch_size per call
        assert result["eligible"] == 10

    async def test_stats(self, db):
        archiver = AuditArchiver(db, retention_days=30)
        stats = archiver.stats
        assert stats["total_archived"] == 0


class TestLocalJSONLBackend:
    async def test_write_batch(self, tmp_path):
        backend = LocalJSONLBackend(base_dir=str(tmp_path / "archive"))
        events = [{"id": "1", "event_type": "login"}]
        path = await backend.write_batch(events, "test_archive")
        assert "test_archive.jsonl" in path

        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["id"] == "1"
