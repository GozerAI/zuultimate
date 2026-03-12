"""Consent router — grant, revoke, and query consent records."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.consent.schemas import (
    ConsentGrantRequest,
    ConsentHistoryResponse,
    ConsentResponse,
    ConsentRevokeRequest,
)
from zuultimate.identity.consent.service import ConsentService

router = APIRouter(prefix="/consent", tags=["consent"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> ConsentService:
    return ConsentService(request.app.state.db)


@router.post(
    "/grant",
    summary="Grant consent",
    response_model=ConsentResponse,
)
async def grant_consent(
    body: ConsentGrantRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Record a new consent grant for the specified purpose."""
    svc = _get_service(request)
    try:
        return await svc.grant(
            tenant_id=body.tenant_id,
            subject_id=body.subject_id,
            purpose=body.purpose,
            version=body.version,
            channel=body.channel,
            ip_hash=body.ip_hash,
            evidence=body.evidence,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/revoke",
    summary="Revoke consent",
    response_model=ConsentResponse,
)
async def revoke_consent(
    body: ConsentRevokeRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Revoke an active consent grant. Does not delete — preserves audit trail."""
    svc = _get_service(request)
    try:
        return await svc.revoke(
            tenant_id=body.tenant_id,
            subject_id=body.subject_id,
            purpose=body.purpose,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/active",
    summary="Get active consents",
    response_model=ConsentHistoryResponse,
)
async def get_active_consents(
    tenant_id: str,
    subject_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Return all active (non-revoked) consent grants for a subject."""
    svc = _get_service(request)
    records = await svc.get_active_consents(tenant_id=tenant_id, subject_id=subject_id)
    return ConsentHistoryResponse(records=records)


@router.get(
    "/history",
    summary="Get consent history",
    response_model=ConsentHistoryResponse,
)
async def get_consent_history(
    tenant_id: str,
    subject_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Return all consent records (granted and revoked) ordered by creation date."""
    svc = _get_service(request)
    records = await svc.get_consent_history(tenant_id=tenant_id, subject_id=subject_id)
    return ConsentHistoryResponse(records=records)
