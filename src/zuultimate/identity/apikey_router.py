"""API key management router."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user, get_service_caller
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.schemas import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyResponse,
)
from zuultimate.identity.tenant_service import TenantService

router = APIRouter(prefix="/api-keys", tags=["api-keys"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> TenantService:
    return TenantService(request.app.state.db)


def _resolve_tenant_id(user: dict, tenant_id: str | None) -> str:
    """Resolve tenant_id: use caller's tenant, or allow service callers to specify one."""
    if tenant_id:
        return tenant_id
    tid = user.get("tenant_id")
    if not tid:
        raise HTTPException(status_code=400, detail="tenant_id required (no tenant in token)")
    return tid


@router.post("", summary="Create API key", response_model=ApiKeyCreateResponse)
async def create_api_key(
    body: ApiKeyCreateRequest,
    request: Request,
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
):
    """Create a new API key. The raw key is returned only once."""
    tid = _resolve_tenant_id(user, tenant_id)
    svc = _get_service(request)
    try:
        return await svc.create_api_key(tenant_id=tid, name=body.name)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("", summary="List API keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    request: Request,
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
):
    """List all API keys for the caller's tenant."""
    tid = _resolve_tenant_id(user, tenant_id)
    svc = _get_service(request)
    return await svc.list_api_keys(tenant_id=tid)


@router.post(
    "/{key_id}/revoke",
    summary="Revoke API key",
    response_model=ApiKeyResponse,
)
async def revoke_api_key(
    key_id: str,
    request: Request,
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
):
    """Deactivate an API key (soft delete)."""
    tid = _resolve_tenant_id(user, tenant_id)
    svc = _get_service(request)
    try:
        return await svc.revoke_api_key(tenant_id=tid, key_id=key_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/{key_id}/rotate",
    summary="Rotate API key",
    response_model=ApiKeyCreateResponse,
)
async def rotate_api_key(
    key_id: str,
    request: Request,
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
):
    """Revoke old key and issue a new one with the same name. Raw key returned once."""
    tid = _resolve_tenant_id(user, tenant_id)
    svc = _get_service(request)
    try:
        return await svc.rotate_api_key(tenant_id=tid, key_id=key_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.delete("/{key_id}", summary="Delete API key")
async def delete_api_key(
    key_id: str,
    request: Request,
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
):
    """Permanently delete an API key."""
    tid = _resolve_tenant_id(user, tenant_id)
    svc = _get_service(request)
    try:
        await svc.delete_api_key(tenant_id=tid, key_id=key_id)
        return {"detail": "API key deleted"}
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# ── Service-to-service endpoint ──────────────────────────────────────────────


@router.post(
    "/service/create",
    summary="Create API key (service-to-service)",
    response_model=ApiKeyCreateResponse,
)
async def service_create_api_key(
    body: ApiKeyCreateRequest,
    request: Request,
    tenant_id: str | None = None,
    _caller: str = Depends(get_service_caller),
):
    """Create an API key via service token. Requires tenant_id query param."""
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id query param required")
    svc = _get_service(request)
    try:
        return await svc.create_api_key(tenant_id=tenant_id, name=body.name)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
