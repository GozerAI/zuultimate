"""DSAR service — manage data subject access request lifecycle."""

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.dsar.models import DSARRequest

# Valid status transitions: from -> set of allowed targets
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "received": {"validated", "rejected"},
    "validated": {"processing"},
    "processing": {"fulfilled", "rejected"},
}


class DSARService:
    """Manage DSAR intake, status advancement, and evidence generation."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def submit(self, tenant_id: str, subject_id: str, request_type: str) -> dict:
        """Create a new DSAR with status=received and 30-day deadline."""
        now = datetime.now(timezone.utc)
        due = now + timedelta(days=30)

        initial_evidence = [
            {"status": "received", "timestamp": now.isoformat(), "note": "DSAR received"}
        ]

        req = DSARRequest(
            tenant_id=tenant_id,
            subject_id=subject_id,
            request_type=request_type,
            status="received",
            received_at=now,
            due_at=due,
            evidence_trail=json.dumps(initial_evidence),
        )

        async with self._db.get_session("identity") as session:
            session.add(req)
            await session.flush()
            return self._to_dict(req)

    async def advance_status(self, dsar_id: str, new_status: str) -> dict:
        """Advance the DSAR through its lifecycle. Validate transitions."""
        async with self._db.get_session("identity") as session:
            result = await session.execute(
                select(DSARRequest).where(DSARRequest.id == dsar_id)
            )
            req = result.scalar_one_or_none()
            if req is None:
                raise NotFoundError(f"DSAR {dsar_id} not found")

            allowed = _VALID_TRANSITIONS.get(req.status, set())
            if new_status not in allowed:
                raise ValidationError(
                    f"Cannot transition from '{req.status}' to '{new_status}'"
                )

            now = datetime.now(timezone.utc)
            req.status = new_status

            if new_status == "fulfilled":
                req.fulfilled_at = now

            trail = json.loads(req.evidence_trail)
            trail.append({
                "status": new_status,
                "timestamp": now.isoformat(),
                "note": f"Status advanced to {new_status}",
            })
            req.evidence_trail = json.dumps(trail)

            await session.flush()
            return self._to_dict(req)

    async def get_request(self, dsar_id: str) -> dict:
        """Fetch a single DSAR by ID."""
        async with self._db.get_session("identity") as session:
            result = await session.execute(
                select(DSARRequest).where(DSARRequest.id == dsar_id)
            )
            req = result.scalar_one_or_none()
            if req is None:
                raise NotFoundError(f"DSAR {dsar_id} not found")
            return self._to_dict(req)

    async def generate_evidence_pack(self, dsar_id: str) -> dict:
        """Return an audit artifact containing request details and full evidence trail."""
        async with self._db.get_session("identity") as session:
            result = await session.execute(
                select(DSARRequest).where(DSARRequest.id == dsar_id)
            )
            req = result.scalar_one_or_none()
            if req is None:
                raise NotFoundError(f"DSAR {dsar_id} not found")

            return {
                "dsar_id": req.id,
                "tenant_id": req.tenant_id,
                "subject_id": req.subject_id,
                "request_type": req.request_type,
                "status": req.status,
                "received_at": req.received_at.isoformat(),
                "due_at": req.due_at.isoformat(),
                "fulfilled_at": req.fulfilled_at.isoformat() if req.fulfilled_at else None,
                "evidence_trail": json.loads(req.evidence_trail),
            }

    async def list_requests(
        self, tenant_id: str | None = None, subject_id: str | None = None
    ) -> list[dict]:
        """List DSAR requests with optional tenant/subject filters."""
        async with self._db.get_session("identity") as session:
            stmt = select(DSARRequest)
            if tenant_id:
                stmt = stmt.where(DSARRequest.tenant_id == tenant_id)
            if subject_id:
                stmt = stmt.where(DSARRequest.subject_id == subject_id)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [self._to_dict(r) for r in rows]

    @staticmethod
    def _to_dict(req: DSARRequest) -> dict:
        """Convert a DSARRequest ORM object to a plain dict."""
        return {
            "id": req.id,
            "tenant_id": req.tenant_id,
            "subject_id": req.subject_id,
            "request_type": req.request_type,
            "status": req.status,
            "received_at": req.received_at.isoformat(),
            "due_at": req.due_at.isoformat(),
            "fulfilled_at": req.fulfilled_at.isoformat() if req.fulfilled_at else None,
            "evidence_trail": json.loads(req.evidence_trail),
        }
