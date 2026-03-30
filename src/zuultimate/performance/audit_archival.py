"""Audit log archival to cold storage.

Item #28: Audit log archival to cold storage.

Provides a service that moves old audit events from the hot database to a cold
storage backend (local JSONL files by default, pluggable for S3/GCS).
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import delete, select, func

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.audit_archival")


class ColdStorageBackend(Protocol):
    """Interface for cold storage writers."""

    async def write_batch(self, events: list[dict[str, Any]], archive_key: str) -> str:
        """Write a batch of events.  Returns the storage location/path."""
        ...


class LocalJSONLBackend:
    """Write archived audit events to local JSONL files."""

    def __init__(self, base_dir: str = "./data/audit_archive"):
        self._base_dir = Path(base_dir)

    async def write_batch(self, events: list[dict[str, Any]], archive_key: str) -> str:
        self._base_dir.mkdir(parents=True, exist_ok=True)
        path = self._base_dir / f"{archive_key}.jsonl"
        with open(path, "a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, default=str) + "\n")
        _log.info("Archived %d events to %s", len(events), path)
        return str(path)


class AuditArchiver:
    """Move old audit events from the hot database to cold storage.

    Parameters
    ----------
    db: DatabaseManager
    backend: ColdStorageBackend implementation (default: LocalJSONLBackend)
    retention_days: Events older than this are eligible for archival.
    batch_size: Max events to archive per invocation.
    """

    def __init__(
        self,
        db: DatabaseManager,
        *,
        backend: ColdStorageBackend | None = None,
        retention_days: int = 90,
        batch_size: int = 5000,
    ):
        self._db = db
        self._backend = backend or LocalJSONLBackend()
        self._retention_days = retention_days
        self._batch_size = batch_size
        self._total_archived = 0

    async def archive(self) -> dict[str, Any]:
        """Archive events older than retention_days.  Returns summary."""
        from zuultimate.identity.models import AuthEvent

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        archived = 0
        deleted = 0

        async with self._db.get_session("identity") as session:
            # Count eligible events
            count_result = await session.execute(
                select(func.count(AuthEvent.id)).where(AuthEvent.created_at < cutoff)
            )
            total_eligible = count_result.scalar() or 0

            if total_eligible == 0:
                return {"archived": 0, "deleted": 0, "eligible": 0}

            # Fetch batch
            result = await session.execute(
                select(AuthEvent)
                .where(AuthEvent.created_at < cutoff)
                .order_by(AuthEvent.created_at)
                .limit(self._batch_size)
            )
            events = result.scalars().all()

            if not events:
                return {"archived": 0, "deleted": 0, "eligible": total_eligible}

            # Serialize to dicts
            batch = []
            event_ids = []
            for evt in events:
                batch.append({
                    "id": evt.id,
                    "event_type": evt.event_type,
                    "tenant_id_hash": evt.tenant_id_hash,
                    "ip_hash": evt.ip_hash,
                    "user_agent_hash": evt.user_agent_hash,
                    "username_hash": evt.username_hash,
                    "metadata_json": evt.metadata_json,
                    "created_at": evt.created_at.isoformat() if evt.created_at else None,
                })
                event_ids.append(evt.id)

            # Write to cold storage
            archive_key = f"audit_{cutoff.strftime('%Y%m%d')}_{int(time.time())}"
            await self._backend.write_batch(batch, archive_key)
            archived = len(batch)

            # Delete archived events from hot database
            await session.execute(
                delete(AuthEvent).where(AuthEvent.id.in_(event_ids))
            )
            deleted = len(event_ids)

        self._total_archived += archived
        _log.info(
            "Audit archival complete: archived=%d, deleted=%d, remaining_eligible=%d",
            archived,
            deleted,
            total_eligible - deleted,
        )

        return {
            "archived": archived,
            "deleted": deleted,
            "eligible": total_eligible,
            "archive_key": archive_key,
        }

    @property
    def stats(self) -> dict[str, int]:
        return {"total_archived": self._total_archived}
