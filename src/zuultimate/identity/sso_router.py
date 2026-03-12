"""SSO router -- OIDC/SAML provider management and login flow."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.schemas import (
    SSOCallbackRequest,
    SSOLoginInitResponse,
    SSOProviderCreate,
    SSOProviderResponse,
)
from zuultimate.identity.sso_service import SSOService

router = APIRouter(prefix="/sso", tags=["sso"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> SSOService:
    return SSOService(request.app.state.db, request.app.state.settings)


@router.post(
    "/providers",
    summary="Create SSO provider",
    response_model=SSOProviderResponse,
    dependencies=[Depends(get_current_user)],
)
async def create_provider(body: SSOProviderCreate, request: Request):
    svc = _get_service(request)
    try:
        return await svc.create_provider(
            name=body.name,
            protocol=body.protocol,
            issuer_url=body.issuer_url,
            client_id=body.client_id,
            client_secret=body.client_secret,
            metadata_url=body.metadata_url,
            tenant_id=body.tenant_id,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/providers",
    summary="List SSO providers",
    response_model=list[SSOProviderResponse],
    dependencies=[Depends(get_current_user)],
)
async def list_providers(
    request: Request,
    tenant_id: str | None = Query(default=None),
):
    svc = _get_service(request)
    return await svc.list_providers(tenant_id=tenant_id)


@router.get("/login/{provider_id}", summary="Initiate SSO login", response_model=SSOLoginInitResponse)
async def initiate_sso_login(
    provider_id: str,
    request: Request,
    redirect_uri: str = Query(default="http://localhost:3000/callback"),
):
    svc = _get_service(request)
    try:
        return await svc.initiate_login(provider_id, redirect_uri)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/callback", summary="Handle SSO callback")
async def sso_callback(body: SSOCallbackRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.handle_callback(body.provider_id, body.code, body.state)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.delete(
    "/providers/{provider_id}",
    summary="Deactivate SSO provider",
    dependencies=[Depends(get_current_user)],
)
async def deactivate_provider(provider_id: str, request: Request):
    svc = _get_service(request)
    try:
        return await svc.deactivate_provider(provider_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
