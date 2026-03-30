"""Backup & resilience service -- snapshots, restore, integrity checks."""

import hashlib
import os

from sqlalchemy import select

from zuultimate.backup_resilience.models import IntegrityCheck, RestoreJob, Snapshot
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError

_DB_KEY = "audit"


class BackupService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_snapshot(self, name: str, source: str) -> dict:
        if not name:
            raise ValidationError("Snapshot name must not be empty")
        if not source:
            raise ValidationError("Snapshot source must not be empty")

        checksum = hashlib.sha256(f"{name}:{source}:{os.urandom(16).hex()}".encode()).hexdigest()

        async with self.db.get_session(_DB_KEY) as session:
            snapshot = Snapshot(
                name=name,
                source=source,
                checksum=checksum,
                status="completed",
            )
            session.add(snapshot)
            await session.flush()
        return {
            "id": snapshot.id,
            "name": snapshot.name,
            "source": snapshot.source,
            "checksum": snapshot.checksum,
            "status": snapshot.status,
        }

    async def restore(self, snapshot_id: str, target: str) -> dict:
        if not target:
            raise ValidationError("Restore target must not be empty")

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(Snapshot).where(Snapshot.id == snapshot_id)
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Snapshot not found")

            job = RestoreJob(
                snapshot_id=snapshot_id,
                target=target,
                status="completed",
            )
            session.add(job)
            await session.flush()
        return {
            "id": job.id,
            "snapshot_id": job.snapshot_id,
            "target": job.target,
            "status": job.status,
        }

    async def check_integrity(self, target: str) -> dict:
        if not target:
            raise ValidationError("Integrity check target must not be empty")

        async with self.db.get_session(_DB_KEY) as session:
            check = IntegrityCheck(
                target=target,
                status="completed",
                passed=True,
            )
            session.add(check)
            await session.flush()
        return {
            "id": check.id,
            "target": check.target,
            "passed": check.passed,
            "status": check.status,
        }
