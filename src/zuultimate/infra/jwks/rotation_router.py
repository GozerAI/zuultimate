"""Admin endpoints for JWKS rotation lifecycle (stampede-free 48-hour cycle)."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from zuultimate.common.auth import get_service_caller

router = APIRouter(prefix="/admin/keys/rotation", tags=["admin"])


class ActivateRequest(BaseModel):
    kid: str


class RetireRequest(BaseModel):
    kid: str


@router.post("/initiate")
async def initiate_rotation(
    request: Request, caller: str = Depends(get_service_caller)
):
    """Start a new key rotation cycle. Adds a PENDING key to JWKS.

    Requires service token auth.
    """
    from zuultimate.infra.jwks.rotation import KeyRotationLifecycle

    km = request.app.state.key_manager
    redis = getattr(request.app.state, "redis", None)
    lifecycle = KeyRotationLifecycle(km, redis=redis)

    result = await lifecycle.initiate_rotation()
    return result


@router.post("/activate")
async def activate_rotation(
    body: ActivateRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    """Activate the PENDING key — promotes to ACTIVE, demotes old ACTIVE to RETIRING.

    Requires service token auth.
    """
    from zuultimate.infra.jwks.rotation import KeyRotationLifecycle

    km = request.app.state.key_manager
    redis = getattr(request.app.state, "redis", None)
    lifecycle = KeyRotationLifecycle(km, redis=redis)

    result = await lifecycle.activate_new_key(body.kid)
    return result


@router.post("/retire")
async def retire_rotation(
    body: RetireRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    """Retire the RETIRING key — removes from JWKS.

    Requires service token auth.
    """
    from zuultimate.infra.jwks.rotation import KeyRotationLifecycle

    km = request.app.state.key_manager
    redis = getattr(request.app.state, "redis", None)
    lifecycle = KeyRotationLifecycle(km, redis=redis)

    result = await lifecycle.retire_old_key(body.kid)
    return result


@router.get("/status")
async def rotation_status(
    request: Request, caller: str = Depends(get_service_caller)
):
    """Get current rotation state of all keys.

    Requires service token auth.
    """
    from zuultimate.infra.jwks.rotation import KeyRotationLifecycle

    km = request.app.state.key_manager
    redis = getattr(request.app.state, "redis", None)
    lifecycle = KeyRotationLifecycle(km, redis=redis)

    return await lifecycle.get_rotation_status()
