"""Workforce SSO and identity router."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.workforce.federation import WorkforceFederationService
from zuultimate.identity.workforce.schemas import (
    SSOCallbackRequest,
    SSOCallbackResponse,
    SSOInitiateRequest,
    SSOInitiateResponse,
    WorkforceUserInfo,
)

router = APIRouter(
    prefix="/workforce", tags=["workforce"], responses=STANDARD_ERRORS
)


def _get_federation(request: Request) -> WorkforceFederationService:
    db = request.app.state.db
    settings = request.app.state.settings
    key_manager = getattr(request.app.state, "key_manager", None)
    return WorkforceFederationService(db, settings, key_manager)


@router.post(
    "/sso/initiate",
    summary="Start SAML/OIDC SSO flow",
    response_model=SSOInitiateResponse,
)
async def sso_initiate(body: SSOInitiateRequest, request: Request):
    svc = _get_federation(request)
    result = await svc.initiate_saml(body.provider_id, body.redirect_uri)
    return SSOInitiateResponse(**result)


@router.post(
    "/sso/callback",
    summary="Handle SAML/OIDC callback",
    response_model=SSOCallbackResponse,
)
async def sso_callback(body: SSOCallbackRequest, request: Request):
    svc = _get_federation(request)
    result = await svc.handle_saml_callback(
        body.provider_id, body.saml_response, body.relay_state
    )
    return SSOCallbackResponse(**result)


@router.get(
    "/me",
    summary="Get current workforce user info",
    response_model=WorkforceUserInfo,
)
async def workforce_me(user: dict = Depends(get_current_user)):
    return WorkforceUserInfo(
        user_id=user.get("user_id", ""),
        username=user.get("username", ""),
        tenant_id=user.get("tenant_id"),
        namespace="workforce",
    )
