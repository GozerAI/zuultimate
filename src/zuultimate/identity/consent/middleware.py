"""Consent-gated middleware — gates routes on active consent for a given purpose."""

from fastapi import Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.identity.consent.service import ConsentService


def requires_consent(purpose: str):
    """Dependency factory — gates a route on active consent for the given purpose.

    Rejects with 403 if the authenticated user has no active consent grant
    for the specified purpose.
    """

    async def _check(
        request: Request,
        user: dict = Depends(get_current_user),
    ) -> dict:
        svc = ConsentService(request.app.state.db)
        tenant_id = user.get("tenant_id")
        user_id = user.get("user_id")

        if not tenant_id or not user_id:
            raise HTTPException(status_code=403, detail=f"Consent required for purpose: {purpose}")

        active = await svc.get_active_consents(tenant_id=tenant_id, subject_id=user_id)
        matching = [r for r in active if r["purpose"] == purpose]
        if not matching:
            raise HTTPException(status_code=403, detail=f"Consent required for purpose: {purpose}")

        return user

    return _check
