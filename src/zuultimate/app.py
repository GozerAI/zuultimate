"""FastAPI application factory."""

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from sqlalchemy import text as sa_text

from zuultimate.common.config import get_settings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.logging import get_logger
from zuultimate.common.metrics import get_metrics_text
from zuultimate.common.middleware import (
    RegionRoutingMiddleware,
    RequestIDMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from zuultimate.common.redis import RedisManager
from zuultimate.common.schemas import ErrorResponse, HealthResponse
from zuultimate.common.tasks import SessionCleanupTask
from zuultimate.infra.cache.session_store import RedisSessionStore
from zuultimate.infra.cache.bloom_filter import DenyListBloomFilter
from zuultimate.infra.audit.pipeline import AuditPipeline

_log = get_logger("zuultimate.app")

_health_cache: dict = {"result": None, "ts": 0.0}
_HEALTH_CACHE_TTL = 10  # seconds


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB engines on startup; dispose on shutdown."""
    settings = get_settings()
    db = DatabaseManager(settings)
    await db.init()

    # Import all models so Base.metadata knows about every table
    import zuultimate.identity.models  # noqa: F401
    import zuultimate.access.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.pos.models  # noqa: F401
    import zuultimate.crm.models  # noqa: F401
    import zuultimate.backup_resilience.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401  -- webhook_configs, webhook_deliveries
    import zuultimate.common.idempotency  # noqa: F401  -- idempotency_records
    import zuultimate.identity.consent.models  # noqa: F401
    import zuultimate.identity.dsar.models  # noqa: F401
    import zuultimate.common.key_manager  # noqa: F401  -- jwks_keys table
    import zuultimate.vault.blind_pass  # noqa: F401  -- blind_pass_tokens
    import zuultimate.vault.cross_service  # noqa: F401  -- cross_service_bindings
    import zuultimate.identity.workforce.models  # noqa: F401  -- workforce tables

    await db.create_all()

    redis = RedisManager(settings.redis_url)
    await redis.connect()

    # Bootstrap RSA key manager for RS256 JWT signing
    from zuultimate.common.key_manager import KeyManager

    region = getattr(settings, "region", "us")
    key_manager = KeyManager(db, region=region)
    await key_manager.ensure_key_exists()

    # Tiered storage: Redis session store
    session_store = RedisSessionStore(redis)

    # Async audit pipeline (in-memory queue; Kafka would replace in production)
    async def _audit_flush(batch: list[dict]) -> None:
        """Bulk-insert audit events into the identity database."""
        from zuultimate.identity.models import AuthEvent

        async with db.get_session("identity") as session:
            for evt in batch:
                session.add(AuthEvent(**evt))

    audit_pipeline = AuditPipeline(_audit_flush)
    await audit_pipeline.start()

    # Bloom filter for token deny list pre-screening
    bloom_filter = DenyListBloomFilter()
    bloom_rebuild_task: asyncio.Task | None = None

    async def _bloom_rebuild_loop() -> None:
        """Periodically rebuild bloom filter from Redis deny list."""
        while True:
            try:
                await asyncio.sleep(60)
                await bloom_filter.rebuild_from_redis(redis)
                _log.debug(
                    "Bloom filter rebuilt (%d items)", bloom_filter.item_count
                )
            except asyncio.CancelledError:
                break
            except Exception:
                _log.warning("Bloom filter rebuild failed", exc_info=True)

    bloom_rebuild_task = asyncio.create_task(_bloom_rebuild_loop())

    app.state.db = db
    app.state.settings = settings
    app.state.redis = redis
    app.state.key_manager = key_manager
    app.state.session_store = session_store
    app.state.audit_pipeline = audit_pipeline
    app.state.bloom_filter = bloom_filter
    app.state.shutting_down = False

    cleanup = SessionCleanupTask(db, interval_seconds=300, max_age_hours=24)
    await cleanup.start()
    app.state.session_cleanup = cleanup

    _log.info("Zuultimate started (env=%s)", settings.environment)
    yield

    # Graceful shutdown
    app.state.shutting_down = True
    _log.info("Shutting down — draining connections")
    await asyncio.sleep(0.5)  # brief drain window for in-flight requests
    if bloom_rebuild_task is not None:
        bloom_rebuild_task.cancel()
        try:
            await bloom_rebuild_task
        except asyncio.CancelledError:
            pass
    await audit_pipeline.stop()
    await cleanup.stop()
    await redis.close()
    await db.close_all()
    _log.info("Shutdown complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        lifespan=lifespan,
    )

    # Middleware — order matters: last added = outermost
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RegionRoutingMiddleware, region=settings.region)

    # ── Global error handlers ──

    @app.exception_handler(ZuulError)
    async def _zuul_error(request: Request, exc: ZuulError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=exc.message, code=exc.code
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="Validation failed",
                code="VALIDATION_ERROR",
                detail=str(exc.errors()),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        _log.error("Unhandled error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal server error", code="INTERNAL_ERROR"
            ).model_dump(),
        )

    # ── Health probes ──

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Detailed health with DB connectivity checks (cached for 10s)."""
        now = time.monotonic()
        if _health_cache["result"] is not None and (now - _health_cache["ts"]) < _HEALTH_CACHE_TTL:
            return _health_cache["result"]

        db: DatabaseManager = app.state.db
        checks: dict[str, str] = {}
        for key in DatabaseManager.DB_KEYS:
            engine = db.engines.get(key)
            if engine is None:
                checks[key] = "missing"
                continue
            try:
                async with engine.connect() as conn:
                    await conn.execute(sa_text("SELECT 1"))
                checks[key] = "ok"
            except Exception:
                checks[key] = "error"

        redis_mgr: RedisManager = app.state.redis
        checks["redis"] = "ok" if redis_mgr.is_available else "unavailable (fallback)"

        all_ok = all(v == "ok" for v in checks.values() if v != "unavailable (fallback)")
        result = HealthResponse(
            status="ok" if all_ok else "degraded",
            version=settings.api_version,
            environment=settings.environment,
            timestamp=datetime.now(timezone.utc),
            checks=checks,
        )
        _health_cache["result"] = result
        _health_cache["ts"] = now
        return result

    @app.get("/health/live")
    async def liveness():
        """Kubernetes liveness probe — always 200 if process is running."""
        return {"status": "alive"}

    @app.get("/health/startup")
    async def startup():
        """Kubernetes startup probe — returns 200 when the process is alive.

        This is a minimal check that does not verify DB or Redis connectivity.
        Used by startupProbe to give the app time to initialize before
        liveness/readiness probes kick in.
        """
        return {"status": "started"}

    @app.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe — checks DB connectivity."""
        if getattr(app.state, "shutting_down", False):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "shutting_down"},
            )
        db: DatabaseManager = app.state.db
        for key in DatabaseManager.DB_KEYS:
            engine = db.engines.get(key)
            if engine is None:
                return JSONResponse(
                    status_code=503,
                    content={"status": "not_ready", "reason": f"{key} db missing"},
                )
            try:
                async with engine.connect() as conn:
                    await conn.execute(sa_text("SELECT 1"))
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"status": "not_ready", "reason": f"{key} db unreachable"},
                )
        return {"status": "ready"}

    # ── JWKS endpoint (public, no auth) ──

    @app.get("/.well-known/jwks.json")
    async def jwks():
        """Serve public keys in JWKS format for RS256 token verification."""
        km = getattr(app.state, "key_manager", None)
        if km is None:
            return JSONResponse(content={"keys": []})

        # Try Redis cache
        redis = getattr(app.state, "redis", None)
        if redis and redis.is_available:
            cached = await redis.get("jwks:cache")
            if cached:
                import json
                return JSONResponse(content=json.loads(cached))

        keys = await km.get_all_public_keys()
        result = {"keys": keys}

        if redis and redis.is_available:
            import json
            await redis.setex("jwks:cache", 60, json.dumps(result))

        return JSONResponse(content=result)

    # ── Prometheus metrics endpoint ──

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        """Expose Prometheus metrics for scraping."""
        body, content_type = get_metrics_text()
        return Response(content=body, media_type=content_type)

    # API v1 router — all module routers grouped under /v1
    v1 = APIRouter(prefix="/v1")

    from zuultimate.identity.router import router as identity_router
    from zuultimate.identity.tenant_router import router as tenant_router
    from zuultimate.identity.sso_router import router as sso_router
    from zuultimate.access.router import router as access_router
    from zuultimate.vault.router import router as vault_router
    from zuultimate.pos.router import router as pos_router
    from zuultimate.crm.router import router as crm_router
    from zuultimate.backup_resilience.router import router as backup_router
    from zuultimate.plugins.router import router as plugins_router
    from zuultimate.common.webhook_router import router as webhook_router
    from zuultimate.identity.phase2_router import router as phase2_router
    from zuultimate.identity.consent.router import router as consent_router
    from zuultimate.identity.dsar.router import router as dsar_router
    from zuultimate.identity.passkey_router import router as passkey_router
    from zuultimate.common.key_rotation_router import router as key_rotation_router
    from zuultimate.infra.jwks.rotation_router import router as jwks_rotation_router
    from zuultimate.vault.blind_pass_router import router as blind_pass_router
    from zuultimate.identity.workforce.router import router as workforce_router
    from zuultimate.identity.workforce.pop_router import router as pop_router
    from zuultimate.identity.workforce.posture_router import router as posture_router
    from zuultimate.identity.apikey_router import router as apikey_router

    v1.include_router(identity_router)
    v1.include_router(tenant_router)
    v1.include_router(sso_router)
    v1.include_router(access_router)
    v1.include_router(vault_router)
    v1.include_router(pos_router)
    v1.include_router(crm_router)
    v1.include_router(backup_router)
    v1.include_router(plugins_router)
    v1.include_router(webhook_router)
    v1.include_router(phase2_router)
    v1.include_router(consent_router)
    v1.include_router(dsar_router)
    v1.include_router(passkey_router)
    v1.include_router(key_rotation_router)
    v1.include_router(jwks_rotation_router)
    v1.include_router(blind_pass_router)
    v1.include_router(workforce_router)
    v1.include_router(pop_router)
    v1.include_router(posture_router)
    v1.include_router(apikey_router)

    app.include_router(v1)

    return app
