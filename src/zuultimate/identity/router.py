"""Identity router -- registration, login, logout, token refresh."""

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import AuthenticationError, ZuulError
from zuultimate.common.logging import get_logger
from zuultimate.common.rate_limit import rate_limit_login
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.auth_events import AuthEventEmitter
from zuultimate.identity.lockout import LockoutService
from zuultimate.identity.mfa_service import MFAService
from zuultimate.common.config import PLAN_ENTITLEMENTS
from zuultimate.identity.schemas import (
    AuthValidateResponse,
    EmailVerificationResponse,
    EmailVerifyRequest,
    IntrospectRequest,
    IntrospectResponse,
    LoginRequest,
    MFAChallengeRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    VerificationTokenResponse,
)
from zuultimate.identity.risk.evaluator import RiskEvaluator
from zuultimate.identity.risk.models import RiskAction
from zuultimate.identity.risk.pwned import PwnedPasswordChecker
from zuultimate.identity.service import IdentityService

_log = get_logger(__name__)

router = APIRouter(prefix="/identity", tags=["identity"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> IdentityService:
    return IdentityService(request.app.state.db, request.app.state.settings)


@router.post(
    "/register",
    summary="Register new user",
    response_model=UserResponse,
    dependencies=[Depends(rate_limit_login)],
)
async def register(body: RegisterRequest, request: Request):
    # Check password against known breaches (non-blocking on failure)
    try:
        checker = PwnedPasswordChecker()
        if await checker.check(body.password):
            raise HTTPException(
                status_code=422,
                detail="Password found in known data breaches — choose a different password",
            )
    except HTTPException:
        raise
    except Exception as exc:
        _log.warning("Pwned password check failed, proceeding: %s", exc)

    svc = _get_service(request)
    try:
        return await svc.register(
            email=body.email,
            username=body.username,
            password=body.password,
            display_name=body.display_name,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _get_lockout(request: Request) -> LockoutService:
    return LockoutService(request.app.state.redis)


def _get_emitter(request: Request) -> AuthEventEmitter:
    return AuthEventEmitter(request.app.state.db)


@router.post(
    "/login",
    summary="Authenticate user",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_login)],
)
async def login(body: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    lockout = _get_lockout(request)
    emitter = _get_emitter(request)

    # Check progressive lockout before attempting auth
    is_locked, remaining = await lockout.check_lockout(client_ip, body.username)
    if is_locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Retry in {remaining}s.",
        )

    svc = _get_service(request)
    try:
        result = await svc.login(username=body.username, password=body.password)
    except AuthenticationError as e:
        await lockout.record_failure(client_ip, body.username)
        await emitter.emit(
            event_type="auth_failure",
            ip=client_ip,
            user_agent=user_agent,
            username=body.username,
        )
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    await lockout.record_success(client_ip, body.username)

    # ── Risk signal evaluation ──
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()
    device_hash = hashlib.sha256(user_agent.encode()).hexdigest()
    risk_context = {
        "ip_hash": ip_hash,
        "user_hash": hashlib.sha256(body.username.encode()).hexdigest(),
        "device_hash": device_hash,
        "country_code": "unknown",
    }
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        risk = await RiskEvaluator(redis).evaluate(risk_context)
        if risk.action == RiskAction.block:
            await emitter.emit(
                event_type="auth_blocked_risk",
                ip=client_ip,
                user_agent=user_agent,
                username=body.username,
                metadata={"risk_score": risk.score},
            )
            raise HTTPException(
                status_code=403,
                detail="Auth blocked by risk engine",
            )
        if risk.action == RiskAction.step_up:
            _log.warning(
                "Risk step-up for user=%s score=%.2f",
                body.username,
                risk.score,
            )

    await emitter.emit(
        event_type="auth_success",
        ip=client_ip,
        user_agent=user_agent,
        username=body.username,
    )
    return result


@router.post(
    "/refresh",
    summary="Refresh access token",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_login)],
)
async def refresh_token(body: RefreshRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.refresh_token(body.refresh_token)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/users/{user_id}", summary="Get user by ID", response_model=UserResponse)
async def get_user(
    user_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.get_user(user_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/logout", summary="Logout current user")
async def logout(request: Request, _user: dict = Depends(get_current_user)):
    svc = _get_service(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = auth[7:]
    await svc.logout(token)
    return {"detail": "Logged out"}


@router.post(
    "/auth/introspect",
    summary="Introspect token validity",
    response_model=IntrospectResponse,
)
async def introspect_token(body: IntrospectRequest, request: Request):
    """Check whether a token is active and return its claims."""
    svc = _get_service(request)
    result = await svc.introspect_token(body.token)
    return IntrospectResponse(**result)


@router.post("/verify-email/send", summary="Send verification email", response_model=VerificationTokenResponse)
async def send_verification(request: Request, user: dict = Depends(get_current_user)):
    svc = _get_service(request)
    try:
        return await svc.create_verification_token(user["user_id"])
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/verify-email/confirm", summary="Confirm email verification", response_model=EmailVerificationResponse)
async def confirm_verification(body: EmailVerifyRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.verify_email(body.token)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def _get_mfa_service(request: Request) -> MFAService:
    return MFAService(request.app.state.db, request.app.state.settings)


@router.post("/mfa/setup", summary="Setup MFA for user", response_model=MFASetupResponse)
async def mfa_setup(request: Request, user: dict = Depends(get_current_user)):
    svc = _get_mfa_service(request)
    try:
        return await svc.setup_totp(user["user_id"])
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/mfa/verify", summary="Verify MFA TOTP code")
async def mfa_verify(
    body: MFAVerifyRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    svc = _get_mfa_service(request)
    try:
        return await svc.verify_totp(user["user_id"], body.code)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/mfa/challenge", summary="Complete MFA challenge", response_model=TokenResponse)
async def mfa_challenge(body: MFAChallengeRequest, request: Request):
    mfa_svc = _get_mfa_service(request)
    try:
        result = await mfa_svc.complete_challenge(body.mfa_token, body.code)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    # Issue full tokens after MFA verification
    id_svc = _get_service(request)
    tokens = await id_svc.issue_tokens_for_user(result["user_id"])

    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_in=request.app.state.settings.access_token_expire_minutes * 60,
    )


@router.get("/auth/validate", summary="Validate token and return tenant context", response_model=AuthValidateResponse)
async def auth_validate(
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Validate the caller's token and return tenant context + entitlements.

    Used by downstream services (TrendScope, etc.) to authenticate requests.
    """
    from zuultimate.identity.models import Tenant

    tenant_id = user.get("tenant_id")
    plan = "starter"

    if tenant_id:
        db = request.app.state.db
        from sqlalchemy import select

        async with db.get_session("identity") as session:
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                plan = tenant.plan

    entitlements = PLAN_ENTITLEMENTS.get(plan, [])

    return AuthValidateResponse(
        user_id=user.get("user_id"),
        username=user.get("username", ""),
        tenant_id=tenant_id,
        plan=plan,
        entitlements=entitlements,
    )


# ── Honeypot endpoint ──


@router.post("/legacy-login", summary="Legacy login endpoint", include_in_schema=False)
async def legacy_login(body: LoginRequest, request: Request):
    """Honeypot -- always returns 200 with fake tokens. Flags all callers as high-risk."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    emitter = _get_emitter(request)
    await emitter.emit(
        event_type="honeypot_trigger",
        ip=client_ip,
        user_agent=user_agent,
        username=body.username,
    )
    _log.warning("Honeypot triggered from ip_hash=%s", hashlib.sha256(client_ip.encode()).hexdigest()[:16])

    return TokenResponse(
        access_token="hp." + "x" * 64,
        refresh_token="hp." + "y" * 64,
        token_type="bearer",
        expires_in=3600,
    )
