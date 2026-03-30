"""Unit tests for BackupService."""

import pytest

from zuultimate.backup_resilience.service import BackupService
from zuultimate.common.exceptions import NotFoundError, ValidationError


@pytest.fixture
def svc(test_db):
    return BackupService(test_db)


# ---------------------------------------------------------------------------
# create_snapshot
# ---------------------------------------------------------------------------


async def test_create_snapshot_success(svc):
    result = await svc.create_snapshot("daily-backup", source="/data/main")
    assert result["name"] == "daily-backup"
    assert result["source"] == "/data/main"
    assert result["status"] == "completed"
    assert len(result["checksum"]) == 64  # SHA-256 hex
    assert "id" in result


async def test_create_snapshot_empty_name_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.create_snapshot("", source="/data")


async def test_create_snapshot_empty_source_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.create_snapshot("backup", source="")


async def test_create_snapshot_unique_checksums(svc):
    a = await svc.create_snapshot("snap-a", source="/data")
    b = await svc.create_snapshot("snap-b", source="/data")
    assert a["checksum"] != b["checksum"]


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------


async def test_restore_success(svc):
    snap = await svc.create_snapshot("snap", source="/data")
    result = await svc.restore(snap["id"], target="/restore/target")
    assert result["snapshot_id"] == snap["id"]
    assert result["target"] == "/restore/target"
    assert result["status"] == "completed"


async def test_restore_nonexistent_snapshot(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.restore("nonexistent", target="/target")


async def test_restore_empty_target_raises(svc):
    snap = await svc.create_snapshot("snap", source="/data")
    with pytest.raises(ValidationError, match="empty"):
        await svc.restore(snap["id"], target="")


# ---------------------------------------------------------------------------
# check_integrity
# ---------------------------------------------------------------------------


async def test_check_integrity_success(svc):
    result = await svc.check_integrity(target="/data/main")
    assert result["target"] == "/data/main"
    assert result["passed"] is True
    assert result["status"] == "completed"
    assert "id" in result


async def test_check_integrity_empty_target_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.check_integrity(target="")
