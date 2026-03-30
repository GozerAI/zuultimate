"""Backup & resilience router -- snapshots, restore, integrity checks."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.backup_resilience.schemas import (
    IntegrityCheckRequest,
    IntegrityCheckResponse,
    RestoreRequest,
    RestoreResponse,
    SnapshotCreate,
    SnapshotResponse,
)
from zuultimate.backup_resilience.service import BackupService
from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS

router = APIRouter(
    prefix="/backup",
    tags=["backup"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> BackupService:
    return BackupService(request.app.state.db)


@router.post("/snapshots", summary="Create backup snapshot", response_model=SnapshotResponse)
async def create_snapshot(body: SnapshotCreate, request: Request):
    svc = _get_service(request)
    try:
        return await svc.create_snapshot(name=body.name, source=body.source)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/restore", summary="Restore from snapshot", response_model=RestoreResponse)
async def restore(body: RestoreRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.restore(snapshot_id=body.snapshot_id, target=body.target)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/integrity-check", summary="Run integrity check", response_model=IntegrityCheckResponse)
async def check_integrity(body: IntegrityCheckRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.check_integrity(target=body.target)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
