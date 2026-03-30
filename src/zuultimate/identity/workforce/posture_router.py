"""Posture change webhook handler -- MDM compliance events."""

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from zuultimate.common.logging import get_logger
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.workforce.models import DevicePosture
from zuultimate.identity.workforce.schemas import PostureWebhookRequest

_log = get_logger("zuultimate.workforce.posture")

router = APIRouter(
    prefix="/workforce/posture", tags=["workforce-posture"], responses=STANDARD_ERRORS
)

# JTI deny-list TTL in seconds (24 hours)
_DENY_TTL = 86400


@router.post("/webhook", summary="MDM compliance change webhook")
async def posture_webhook(body: PostureWebhookRequest, request: Request):
    """Handle MDM compliance change.

    When a device becomes non-compliant, revokes all sessions for that
    device_id by adding their JTIs to the Redis deny-list.
    """
    db = request.app.state.db
    redis = getattr(request.app.state, "redis", None)

    if body.compliance_status != "non_compliant":
        return {"status": "ok", "action": "none", "revoked_count": 0}

    # Find all posture records for this device
    async with db.get_session("identity") as session:
        result = await session.execute(
            select(DevicePosture).where(DevicePosture.device_id == body.device_id)
        )
        postures = result.scalars().all()

    if not postures:
        return {"status": "ok", "action": "no_device_found", "revoked_count": 0}

    # Collect user_ids from affected devices
    user_ids = {p.user_id for p in postures}

    revoked_count = 0
    if redis:
        # Find active sessions for these users and deny their JTIs
        from zuultimate.identity.models import UserSession

        async with db.get_session("identity") as session:
            for uid in user_ids:
                result = await session.execute(
                    select(UserSession).where(
                        UserSession.user_id == uid,
                        UserSession.is_consumed == False,  # noqa: E712
                    )
                )
                sessions = result.scalars().all()
                for us in sessions:
                    # Mark session consumed
                    us.is_consumed = True
                    revoked_count += 1

                    # Add to Redis deny-list using a synthetic JTI key
                    try:
                        await redis.setex(
                            f"jti:deny:{us.id}", _DENY_TTL, "posture_revoked"
                        )
                    except Exception:
                        pass  # Redis unavailable -- best effort

    _log.warning(
        "Posture webhook: device=%s non_compliant, revoked=%d sessions",
        body.device_id,
        revoked_count,
    )

    return {"status": "ok", "action": "sessions_revoked", "revoked_count": revoked_count}
