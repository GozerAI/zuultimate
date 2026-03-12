"""Authentication & authorization middleware."""

import hashlib
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from zuultimate.common.security import decode_jwt

_bearer = HTTPBearer()


async def _authenticate_api_key(token: str, request: Request) -> dict:
    """Authenticate via API key (gzr_ prefix). Returns user-like dict."""
    from zuultimate.identity.models import ApiKey, Tenant

    db = request.app.state.db
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    prefix = token[:8]

    async with db.get_session("identity") as session:
        result = await session.execute(
            select(ApiKey).where(ApiKey.key_prefix == prefix, ApiKey.is_active == True)
        )
        api_key = result.scalar_one_or_none()
        if api_key is None or api_key.key_hash != key_hash:
            raise HTTPException(status_code=401, detail="Invalid API key")

        # Update last_used_at
        api_key.last_used_at = datetime.now(timezone.utc)
        await session.flush()

        # Verify tenant is active
        result = await session.execute(
            select(Tenant).where(Tenant.id == api_key.tenant_id, Tenant.is_active == True)
        )
        tenant = result.scalar_one_or_none()
        if tenant is None:
            raise HTTPException(status_code=401, detail="Tenant not found or inactive")

    return {
        "user_id": None,
        "username": f"apikey:{api_key.name}",
        "tenant_id": api_key.tenant_id,
    }


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """Validate JWT access token or API key and return user context."""
    token = credentials.credentials

    # API key path
    if token.startswith("gzr_"):
        return await _authenticate_api_key(token, request)

    # JWT path
    settings = request.app.state.settings

    try:
        payload = decode_jwt(token, settings.secret_key)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Validate session exists in DB
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = request.app.state.db

    from zuultimate.identity.models import User, UserSession

    async with db.get_session("identity") as session:
        result = await session.execute(
            select(UserSession).where(UserSession.access_token_hash == token_hash)
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(status_code=401, detail="Session revoked or expired")

        result = await session.execute(
            select(User).where(User.id == user_id, User.is_active == True)
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(status_code=401, detail="User not found or inactive")

    return {
        "user_id": user_id,
        "username": payload.get("username", ""),
        "tenant_id": payload.get("tenant_id"),
    }


async def get_service_caller(request: Request) -> str:
    """Validates internal service-to-service token. Returns service name."""
    token = request.headers.get("X-Service-Token", "")
    settings = request.app.state.settings
    if not token or not settings.service_token or token != settings.service_token:
        raise HTTPException(status_code=401, detail="Invalid service token")
    return "internal"


async def get_tenant_id(user: dict = Depends(get_current_user)) -> str | None:
    """Extract tenant_id from JWT claims. Returns None for global users."""
    return user.get("tenant_id")


def require_access(resource: str, action: str) -> Callable:
    """Dependency factory: checks the authenticated user has a matching access policy.

    Usage::

        @router.post("/sensitive", dependencies=[Depends(require_access("vault/*", "write"))])
        async def do_sensitive():
            ...
    """

    async def _check(
        request: Request,
        user: dict = Depends(get_current_user),
    ) -> dict:
        from zuultimate.access.service import AccessService

        db = request.app.state.db
        svc = AccessService(db)
        result = await svc.check_access(
            user_id=user["user_id"], resource=resource, action=action,
        )
        if not result["allowed"]:
            raise HTTPException(status_code=403, detail=result["reason"])
        return user

    return _check
