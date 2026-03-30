"""Admin endpoint for RSA key rotation."""

from fastapi import APIRouter, Depends, Request

from zuultimate.common.auth import get_service_caller

router = APIRouter(prefix="/admin/keys", tags=["admin"])


@router.post("/rotate")
async def rotate_keys(request: Request, caller: str = Depends(get_service_caller)):
    """Rotate RSA signing keys. Requires service token auth.

    Lifecycle: RETIRING → RETIRED, ACTIVE → RETIRING, new key → ACTIVE.
    Returns the kid of the newly generated ACTIVE key.
    """
    km = request.app.state.key_manager
    new_kid = await km.rotate()

    # Invalidate JWKS cache so the next JWKS fetch reflects the new key set
    redis = getattr(request.app.state, "redis", None)
    if redis and getattr(redis, "is_available", False):
        await redis.delete("jwks:cache")

    return {"kid": new_kid, "status": "rotated"}


@router.get("/")
async def list_keys(request: Request, caller: str = Depends(get_service_caller)):
    """List all non-retired keys in JWKS format. Requires service token auth."""
    km = request.app.state.key_manager
    keys = await km.get_all_public_keys()
    return {"keys": keys}
