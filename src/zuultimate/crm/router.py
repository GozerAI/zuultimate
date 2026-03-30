"""CRM router -- configs, sync jobs."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.crm.schemas import (
    CRMConfigCreate,
    CRMConfigResponse,
    SyncJobResponse,
    SyncStartRequest,
)
from zuultimate.crm.adapters import get_adapter, list_adapters
from zuultimate.crm.service import CRMService

router = APIRouter(
    prefix="/crm",
    tags=["crm"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> CRMService:
    return CRMService(request.app.state.db)


@router.post("/configs", summary="Create CRM config", response_model=CRMConfigResponse)
async def create_config(body: CRMConfigCreate, request: Request):
    svc = _get_service(request)
    try:
        return await svc.create_config(provider=body.provider, api_url=body.api_url)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/sync", summary="Start CRM sync job", response_model=SyncJobResponse)
async def start_sync(body: SyncStartRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.start_sync(config_id=body.config_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/sync/{job_id}", summary="Get sync job status", response_model=SyncJobResponse)
async def get_sync_status(job_id: str, request: Request):
    svc = _get_service(request)
    try:
        return await svc.get_sync_status(job_id=job_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/adapters", summary="List CRM adapters")
async def available_adapters():
    """List all registered CRM provider adapters."""
    return {"adapters": list_adapters()}


@router.post("/adapters/{provider}/test", summary="Test CRM adapter connectivity")
async def test_adapter(provider: str, request: Request):
    """Test connectivity to a CRM provider."""
    try:
        adapter = get_adapter(provider, api_url="https://api.example.com")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    result = await adapter.test_connection()
    return result


@router.post("/adapters/{provider}/fetch", summary="Fetch contacts from adapter")
async def fetch_contacts(provider: str, request: Request):
    """Fetch sample contacts from a CRM provider adapter."""
    try:
        adapter = get_adapter(provider, api_url="https://api.example.com")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    contacts = await adapter.fetch_contacts(limit=10)
    return {"contacts": contacts, "count": len(contacts)}
