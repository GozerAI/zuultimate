"""Tenant management router."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user, get_service_caller
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.schemas import (
    TenantCreateRequest,
    TenantProvisionRequest,
    TenantProvisionResponse,
    TenantResponse,
)
from zuultimate.identity.tenant_service import TenantService

router = APIRouter(prefix="/tenants", tags=["tenants"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> TenantService:
    return TenantService(request.app.state.db)


@router.post("", summary="Create tenant", response_model=TenantResponse)
async def create_tenant(
    body: TenantCreateRequest,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.create_tenant(name=body.name, slug=body.slug)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("", summary="List all tenants", response_model=list[TenantResponse])
async def list_tenants(
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    return await svc.list_tenants()


@router.get("/{tenant_id}", summary="Get tenant by ID", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.get_tenant(tenant_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/{tenant_id}/deactivate", summary="Deactivate tenant", response_model=TenantResponse)
async def deactivate_tenant(
    tenant_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.deactivate_tenant(tenant_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/provision",
    summary="Provision new tenant (service-to-service)",
    response_model=TenantProvisionResponse,
)
async def provision_tenant(
    body: TenantProvisionRequest,
    request: Request,
    _caller: str = Depends(get_service_caller),
):
    svc = _get_service(request)
    try:
        return await svc.provision_tenant(
            name=body.name,
            slug=body.slug,
            owner_email=body.owner_email,
            owner_username=body.owner_username,
            owner_password=body.owner_password,
            plan=body.plan,
            stripe_customer_id=body.stripe_customer_id,
            stripe_subscription_id=body.stripe_subscription_id,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
