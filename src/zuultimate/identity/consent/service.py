"""Consent service — grant, revoke, and query consent records."""

import json
from datetime import datetime, timezone

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError
from zuultimate.identity.consent.models import ConsentRecord

_DB_KEY = "identity"


class ConsentService:
    """Manage granular consent grants and revocations."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def _record_to_dict(self, record: ConsentRecord) -> dict:
        """Convert a ConsentRecord ORM instance to a plain dict."""
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "subject_id": record.subject_id,
            "purpose": record.purpose,
            "granted": record.granted,
            "granted_at": record.granted_at.isoformat() if record.granted_at else None,
            "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
            "version": record.version,
            "channel": record.channel,
        }

    async def grant(
        self,
        tenant_id: str,
        subject_id: str,
        purpose: str,
        version: str = "1.0",
        channel: str = "api",
        ip_hash: str = "",
        evidence: dict | None = None,
    ) -> dict:
        """Create a new consent grant record."""
        now = datetime.now(timezone.utc)
        record = ConsentRecord(
            tenant_id=tenant_id,
            subject_id=subject_id,
            purpose=purpose,
            granted=True,
            granted_at=now,
            version=version,
            channel=channel,
            ip_hash=ip_hash,
            evidence_blob=json.dumps(evidence) if evidence else "{}",
        )
        async with self.db.get_session(_DB_KEY) as session:
            session.add(record)
            await session.flush()
            return self._record_to_dict(record)

    async def revoke(self, tenant_id: str, subject_id: str, purpose: str) -> dict:
        """Revoke an active consent grant. Raise NotFoundError if none exists."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ConsentRecord).where(
                    ConsentRecord.tenant_id == tenant_id,
                    ConsentRecord.subject_id == subject_id,
                    ConsentRecord.purpose == purpose,
                    ConsentRecord.granted == True,
                    ConsentRecord.revoked_at.is_(None),
                )
            )
            record = result.scalar_one_or_none()
            if record is None:
                raise NotFoundError("No active consent grant found for the given purpose")

            record.granted = False
            record.revoked_at = datetime.now(timezone.utc)
            await session.flush()
            return self._record_to_dict(record)

    async def get_active_consents(self, tenant_id: str, subject_id: str) -> list[dict]:
        """Return all active (non-revoked) consent grants for a subject."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ConsentRecord).where(
                    ConsentRecord.tenant_id == tenant_id,
                    ConsentRecord.subject_id == subject_id,
                    ConsentRecord.granted == True,
                    ConsentRecord.revoked_at.is_(None),
                )
            )
            return [self._record_to_dict(r) for r in result.scalars().all()]

    async def get_consent_history(self, tenant_id: str, subject_id: str) -> list[dict]:
        """Return all consent records (granted and revoked) ordered by created_at desc."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(ConsentRecord)
                .where(
                    ConsentRecord.tenant_id == tenant_id,
                    ConsentRecord.subject_id == subject_id,
                )
                .order_by(ConsentRecord.created_at.desc())
            )
            return [self._record_to_dict(r) for r in result.scalars().all()]
