"""DSAR privacy router — data subject access request endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.metrics import DSAR_REQUESTS_TOTAL
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.dsar.schemas import (
    DSARAdvanceRequest,
    DSARResponse,
    DSARSubmitRequest,
)
from zuultimate.identity.dsar.service import DSARService

router = APIRouter(
    prefix="/privacy",
    tags=["privacy"],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> DSARService:
    return DSARService(request.app.state.db)


def _enrich_overdue(data: dict) -> DSARResponse:
    """Build a DSARResponse, computing is_overdue from due_at and status."""
    is_overdue = False
    if data["status"] not in ("fulfilled", "rejected"):
        due_at = datetime.fromisoformat(data["due_at"])
        if due_at < datetime.now(timezone.utc):
            is_overdue = True
    return DSARResponse(**data, is_overdue=is_overdue)


@router.post(
    "/dsar",
    summary="Submit a new DSAR",
    response_model=DSARResponse,
)
async def submit_dsar(
    body: DSARSubmitRequest,
    user: dict = Depends(get_current_user),
    svc: DSARService = Depends(_get_service),
):
    try:
        result = await svc.submit(
            tenant_id=body.tenant_id,
            subject_id=body.subject_id,
            request_type=body.request_type,
        )
        DSAR_REQUESTS_TOTAL.labels(type=body.request_type, status="submitted").inc()
        return _enrich_overdue(result)
    except ZuulError as e:
        DSAR_REQUESTS_TOTAL.labels(type=body.request_type, status="error").inc()
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/dsar/{dsar_id}",
    summary="Get a DSAR by ID",
    response_model=DSARResponse,
)
async def get_dsar(
    dsar_id: str,
    user: dict = Depends(get_current_user),
    svc: DSARService = Depends(_get_service),
):
    try:
        result = await svc.get_request(dsar_id)
        return _enrich_overdue(result)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/dsar/{dsar_id}/advance",
    summary="Advance DSAR status",
    response_model=DSARResponse,
)
async def advance_dsar(
    dsar_id: str,
    body: DSARAdvanceRequest,
    user: dict = Depends(get_current_user),
    svc: DSARService = Depends(_get_service),
):
    try:
        result = await svc.advance_status(dsar_id, body.status)
        return _enrich_overdue(result)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/dsar/{dsar_id}/evidence",
    summary="Get DSAR evidence pack",
)
async def get_evidence_pack(
    dsar_id: str,
    user: dict = Depends(get_current_user),
    svc: DSARService = Depends(_get_service),
):
    try:
        return await svc.generate_evidence_pack(dsar_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/dsar",
    summary="List DSAR requests",
    response_model=list[DSARResponse],
)
async def list_dsars(
    tenant_id: str | None = None,
    subject_id: str | None = None,
    user: dict = Depends(get_current_user),
    svc: DSARService = Depends(_get_service),
):
    try:
        results = await svc.list_requests(tenant_id=tenant_id, subject_id=subject_id)
        return [_enrich_overdue(r) for r in results]
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
