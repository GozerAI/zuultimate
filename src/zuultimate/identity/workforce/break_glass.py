"""Break glass emergency access with dual approval."""

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.common.models import generate_uuid
from zuultimate.identity.workforce.models import BreakGlassSession

_log = get_logger("zuultimate.workforce.break_glass")

# Maximum break-glass session duration
_MAX_TTL_HOURS = 2


class BreakGlassService:
    """Manages break-glass emergency access with dual-approval workflow."""

    def __init__(self, db: DatabaseManager, settings=None):
        self.db = db
        self.settings = settings

    async def initiate(
        self, user_id: str, reason: str, tenant_id: str | None = None
    ) -> dict:
        """Start break glass session. Requires dual approval."""
        session_id = generate_uuid()
        audit_tag = f"bg-{os.urandom(8).hex()}"

        async with self.db.get_session("identity") as session:
            bg = BreakGlassSession(
                id=session_id,
                user_id=user_id,
                reason=reason,
                status="pending",
                audit_tag=audit_tag,
                tenant_id=tenant_id,
            )
            session.add(bg)

        _log.warning(
            "Break-glass initiated id=%s user=%s tag=%s",
            session_id, user_id, audit_tag,
        )
        return {
            "id": session_id,
            "user_id": user_id,
            "reason": reason,
            "status": "pending",
            "first_approver_id": None,
            "second_approver_id": None,
            "activated_at": None,
            "expires_at": None,
            "audit_tag": audit_tag,
            "tenant_id": tenant_id,
        }

    async def approve(self, session_id: str, approver_id: str) -> dict:
        """First or second approval. Activates on second approval. Max 2hr TTL."""
        now = datetime.now(timezone.utc)

        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(BreakGlassSession).where(BreakGlassSession.id == session_id)
            )
            bg = result.scalar_one_or_none()
            if bg is None:
                raise ValueError(f"Break-glass session {session_id} not found")
            if bg.status not in ("pending", "partially_approved"):
                raise ValueError(
                    f"Session {session_id} not pending (status={bg.status})"
                )
            if bg.user_id == approver_id:
                raise ValueError("Requestor cannot approve own break-glass session")

            if bg.first_approver_id is None:
                # First approval
                bg.first_approver_id = approver_id
                bg.status = "partially_approved"
                _log.info(
                    "Break-glass first approval id=%s approver=%s",
                    session_id, approver_id,
                )
            elif bg.first_approver_id == approver_id:
                raise ValueError("Same approver cannot provide both approvals")
            else:
                # Second approval -- activate
                bg.second_approver_id = approver_id
                bg.status = "active"
                bg.activated_at = now
                bg.expires_at = now + timedelta(hours=_MAX_TTL_HOURS)
                _log.warning(
                    "Break-glass ACTIVATED id=%s tag=%s expires=%s",
                    session_id, bg.audit_tag, bg.expires_at,
                )

            return {
                "id": bg.id,
                "user_id": bg.user_id,
                "reason": bg.reason,
                "status": bg.status,
                "first_approver_id": bg.first_approver_id,
                "second_approver_id": bg.second_approver_id,
                "activated_at": bg.activated_at,
                "expires_at": bg.expires_at,
                "audit_tag": bg.audit_tag,
                "tenant_id": bg.tenant_id,
            }

    async def deactivate(self, session_id: str) -> dict:
        """Manually end a break glass session."""
        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(BreakGlassSession).where(BreakGlassSession.id == session_id)
            )
            bg = result.scalar_one_or_none()
            if bg is None:
                raise ValueError(f"Break-glass session {session_id} not found")

            bg.status = "deactivated"
            _log.warning("Break-glass deactivated id=%s tag=%s", session_id, bg.audit_tag)

            return {
                "id": bg.id,
                "user_id": bg.user_id,
                "reason": bg.reason,
                "status": "deactivated",
                "first_approver_id": bg.first_approver_id,
                "second_approver_id": bg.second_approver_id,
                "activated_at": bg.activated_at,
                "expires_at": bg.expires_at,
                "audit_tag": bg.audit_tag,
                "tenant_id": bg.tenant_id,
            }
