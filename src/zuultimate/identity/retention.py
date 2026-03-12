"""Data retention enforcement -- identifies expired records and emits audit events."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete, func, select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.identity.auth_events import AuthEventEmitter
from zuultimate.identity.models import AuthEvent, Tenant

try:
    from zuultimate.identity.consent.models import ConsentRecord
except ImportError:  # pragma: no cover
    ConsentRecord = None  # type: ignore[assignment,misc]

_log = get_logger("zuultimate.retention")


class DataRetentionJob:
    """Scan tenants for expired records and optionally purge them."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db
        self._emitter = AuthEventEmitter(db)

    async def scan(self, dry_run: bool = True) -> dict:
        """Scan all tenants for records that exceed their retention window.

        Args:
            dry_run: When True (default) emit "would purge" audit events but
                     leave records intact. When False delete expired records
                     and emit "purged" audit events.

        Returns:
            Summary dict with tenant_count, expired_records_found, purged flag,
            and per-record details.
        """
        now = datetime.now(timezone.utc)
        details: list[dict] = []

        # Load all tenants
        async with self._db.get_session("identity") as session:
            result = await session.execute(select(Tenant))
            tenants = list(result.scalars().all())

        tenant_count = len(tenants)

        for tenant in tenants:
            cutoff = now - timedelta(days=tenant.default_retention_days)
            tenant_details = await self._scan_tenant(tenant, cutoff, dry_run)
            details.extend(tenant_details)

        expired_count = len(details)

        # Emit a summary audit event
        await self._emitter.emit(
            event_type="retention_scan",
            ip="system",
            metadata={
                "tenant_count": tenant_count,
                "expired_records_found": expired_count,
                "purged": not dry_run,
                "dry_run": dry_run,
            },
        )

        _log.info(
            "retention scan complete: tenants=%d expired=%d dry_run=%s",
            tenant_count,
            expired_count,
            dry_run,
        )

        return {
            "tenant_count": tenant_count,
            "expired_records_found": expired_count,
            "purged": not dry_run,
            "details": details,
        }

    async def _scan_tenant(
        self, tenant: Tenant, cutoff: datetime, dry_run: bool,
    ) -> list[dict]:
        """Scan a single tenant for expired consent records and auth events."""
        now = datetime.now(timezone.utc)
        details: list[dict] = []

        # --- Consent records ---
        if ConsentRecord is not None:
            details.extend(
                await self._process_table(
                    table_name="consent_records",
                    model=ConsentRecord,
                    tenant_id=tenant.id,
                    cutoff=cutoff,
                    now=now,
                    dry_run=dry_run,
                    tenant_id_column=ConsentRecord.tenant_id,
                    created_at_column=ConsentRecord.created_at,
                )
            )

        # --- Auth events ---
        details.extend(
            await self._process_table(
                table_name="auth_events",
                model=AuthEvent,
                tenant_id=tenant.id,
                cutoff=cutoff,
                now=now,
                dry_run=dry_run,
                tenant_id_column=None,  # auth_events use hashed tenant_id
                created_at_column=AuthEvent.created_at,
            )
        )

        return details

    async def _process_table(
        self,
        *,
        table_name: str,
        model,
        tenant_id: str,
        cutoff: datetime,
        now: datetime,
        dry_run: bool,
        tenant_id_column,
        created_at_column,
    ) -> list[dict]:
        """Find and optionally purge expired records in a single table."""
        details: list[dict] = []

        async with self._db.get_session("identity") as session:
            query = select(model).where(created_at_column < cutoff)
            if tenant_id_column is not None:
                query = query.where(tenant_id_column == tenant_id)

            result = await session.execute(query)
            expired = list(result.scalars().all())

            for record in expired:
                created = record.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (now - created).days
                details.append({
                    "table": table_name,
                    "record_id": record.id,
                    "tenant_id": tenant_id,
                    "age_days": age_days,
                })

            if not dry_run and expired:
                ids = [r.id for r in expired]
                await session.execute(
                    sa_delete(model).where(model.id.in_(ids))
                )

        return details
