"""Just-In-Time access grant service."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.common.models import generate_uuid
from zuultimate.identity.workforce.models import JITGrant

_log = get_logger("zuultimate.workforce.jit")

# Maximum JIT grant duration
_MAX_TTL_HOURS = 4


class JITService:
    """Manages just-in-time access grants with approval workflow."""

    def __init__(self, db: DatabaseManager, settings=None):
        self.db = db
        self.settings = settings

    async def request_grant(
        self, user_id: str, scope: str, reason: str, tenant_id: str | None = None
    ) -> dict:
        """Request a JIT access grant. Returns pending grant."""
        grant_id = generate_uuid()
        now = datetime.now(timezone.utc)

        async with self.db.get_session("identity") as session:
            grant = JITGrant(
                id=grant_id,
                user_id=user_id,
                scope=scope,
                reason=reason,
                status="pending",
                requested_at=now,
                tenant_id=tenant_id,
            )
            session.add(grant)

        _log.info("JIT grant requested id=%s user=%s scope=%s", grant_id, user_id, scope)
        return {
            "id": grant_id,
            "user_id": user_id,
            "scope": scope,
            "reason": reason,
            "status": "pending",
            "requested_at": now,
            "approved_at": None,
            "expires_at": None,
            "approved_by": None,
            "tenant_id": tenant_id,
        }

    async def approve_grant(self, grant_id: str, approver_id: str) -> dict:
        """Approve a pending JIT grant. Max 4-hour TTL."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=_MAX_TTL_HOURS)

        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JITGrant).where(JITGrant.id == grant_id)
            )
            grant = result.scalar_one_or_none()
            if grant is None:
                raise ValueError(f"Grant {grant_id} not found")
            if grant.status != "pending":
                raise ValueError(f"Grant {grant_id} is not pending (status={grant.status})")
            if grant.user_id == approver_id:
                raise ValueError("Cannot self-approve JIT grant")

            grant.status = "active"
            grant.approved_by = approver_id
            grant.approved_at = now
            grant.expires_at = expires

        _log.info("JIT grant approved id=%s approver=%s", grant_id, approver_id)
        return {
            "id": grant.id,
            "user_id": grant.user_id,
            "scope": grant.scope,
            "reason": grant.reason,
            "status": "active",
            "approved_by": approver_id,
            "approved_at": now,
            "expires_at": expires,
            "requested_at": grant.requested_at,
            "tenant_id": grant.tenant_id,
        }

    async def revoke_grant(self, grant_id: str) -> dict:
        """Revoke an active JIT grant."""
        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JITGrant).where(JITGrant.id == grant_id)
            )
            grant = result.scalar_one_or_none()
            if grant is None:
                raise ValueError(f"Grant {grant_id} not found")

            grant.status = "revoked"

        _log.info("JIT grant revoked id=%s", grant_id)
        return {
            "id": grant.id,
            "user_id": grant.user_id,
            "scope": grant.scope,
            "status": "revoked",
            "reason": grant.reason,
            "approved_by": grant.approved_by,
            "approved_at": grant.approved_at,
            "expires_at": grant.expires_at,
            "requested_at": grant.requested_at,
            "tenant_id": grant.tenant_id,
        }

    async def check_active_grant(
        self, user_id: str, scope: str
    ) -> dict | None:
        """Check if user has an active, non-expired grant for scope."""
        now = datetime.now(timezone.utc)
        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JITGrant).where(
                    JITGrant.user_id == user_id,
                    JITGrant.scope == scope,
                    JITGrant.status == "active",
                )
            )
            grant = result.scalar_one_or_none()
            if grant is None:
                return None

            if grant.expires_at and grant.expires_at.replace(tzinfo=timezone.utc) < now:
                return None

            return {
                "id": grant.id,
                "user_id": grant.user_id,
                "scope": grant.scope,
                "status": grant.status,
                "expires_at": grant.expires_at,
                "tenant_id": grant.tenant_id,
            }
