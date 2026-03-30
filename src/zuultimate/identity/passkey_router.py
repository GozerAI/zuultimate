"""Passkey (FIDO2/WebAuthn) router -- registration and authentication endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.passkey_service import PasskeyService
from zuultimate.identity.schemas import (
    PasskeyAuthBeginRequest,
    PasskeyAuthBeginResponse,
    PasskeyAuthCompleteRequest,
    PasskeyRegisterBeginResponse,
    PasskeyRegisterCompleteRequest,
)

router = APIRouter(prefix="/passkey", tags=["passkey"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> PasskeyService:
    return PasskeyService(
        request.app.state.db,
        request.app.state.settings,
        key_manager=getattr(request.app.state, "key_manager", None),
    )


@router.post(
    "/register/begin",
    summary="Begin passkey registration",
    response_model=PasskeyRegisterBeginResponse,
)
async def register_begin(
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Start the WebAuthn registration ceremony for the authenticated user."""
    svc = _get_service(request)
    try:
        return await svc.begin_registration(user["user_id"])
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/register/complete",
    summary="Complete passkey registration",
)
async def register_complete(
    body: PasskeyRegisterCompleteRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Complete the WebAuthn registration ceremony and store the credential."""
    svc = _get_service(request)
    try:
        return await svc.complete_registration(
            user_id=user["user_id"],
            credential_response=body.credential,
            challenge=body.challenge,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/auth/begin",
    summary="Begin passkey authentication",
    response_model=PasskeyAuthBeginResponse,
)
async def auth_begin(
    body: PasskeyAuthBeginRequest,
    request: Request,
):
    """Start the WebAuthn authentication ceremony."""
    svc = _get_service(request)
    user_id = ""

    # If username hint provided, resolve to user_id
    if body.username:
        from sqlalchemy import select
        from zuultimate.identity.models import User

        async with request.app.state.db.get_session("identity") as session:
            result = await session.execute(
                select(User).where(User.username == body.username, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user:
                user_id = user.id

    try:
        return await svc.begin_authentication(user_id=user_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/auth/complete",
    summary="Complete passkey authentication",
)
async def auth_complete(
    body: PasskeyAuthCompleteRequest,
    request: Request,
):
    """Complete the WebAuthn authentication ceremony and issue tokens."""
    svc = _get_service(request)
    try:
        return await svc.complete_authentication(
            credential_response=body.credential,
            challenge=body.challenge,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
