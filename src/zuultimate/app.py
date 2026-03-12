"""FastAPI application factory."""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sqlalchemy import text as sa_text

from zuultimate.common.config import get_settings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.logging import get_logger
from zuultimate.common.middleware import RequestIDMiddleware, RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from zuultimate.common.redis import RedisManager
from zuultimate.common.schemas import ErrorResponse, HealthResponse
from zuultimate.common.tasks import SessionCleanupTask

_log = get_logger("zuultimate.app")

_health_cache: dict = {"result": None, "ts": 0.0}
_HEALTH_CACHE_TTL = 10  # seconds


def _try_import(module_path: str):
    """Attempt to import a module, logging a warning if it is a stub."""
    try:
        __import__(module_path)
    except ImportError:
        _log.info(
            "Module %s not available (requires commercial license)", module_path
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB engines on startup; dispose on shutdown."""
    settings = get_settings()
    db = DatabaseManager(settings)
    await db.init()

    # Import all models so Base.metadata knows about every table
    # Community modules (always available)
    import zuultimate.identity.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401
    import zuultimate.common.idempotency  # noqa: F401

    # Pro/Enterprise modules (graceful degradation if stubbed)
    _try_import("zuultimate.access.models")
    _try_import("zuultimate.pos.models")
    _try_import("zuultimate.crm.models")
    _try_import("zuultimate.backup_resilience.models")
    _try_import("zuultimate.ai_security.models")

    await db.create_all()

    redis = RedisManager(settings.redis_url)
    await redis.connect()

    app.state.db = db
    app.state.settings = settings
    app.state.redis = redis
    app.state.shutting_down = False

    cleanup = SessionCleanupTask(db, interval_seconds=300, max_age_hours=24)
    await cleanup.start()
    app.state.session_cleanup = cleanup

    _log.info("Zuultimate started (env=%s)", settings.environment)
    yield

    # Graceful shutdown
    app.state.shutting_down = True
    _log.info("Shutting down \u2014 draining connections")
    await asyncio.sleep(0.5)  # brief drain window for in-flight requests
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

    # Middleware
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

    # Global error handlers

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

    # Health probes

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
        """Kubernetes liveness probe."""
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe."""
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

    # API v1 router
    v1 = APIRouter(prefix="/v1")

    # Community routers (always available)
    from zuultimate.identity.router import router as identity_router
    from zuultimate.identity.tenant_router import router as tenant_router
    from zuultimate.vault.router import router as vault_router
    from zuultimate.common.webhook_router import router as webhook_router
    from zuultimate.identity.phase2_router import router as phase2_router

    v1.include_router(identity_router)
    v1.include_router(tenant_router)
    v1.include_router(vault_router)
    v1.include_router(webhook_router)
    v1.include_router(phase2_router)

    # Pro/Enterprise routers (graceful degradation if stubbed)
    _optional_routers = [
        ("zuultimate.ai_security.router", "router", "ai_security"),
        ("zuultimate.identity.sso_router", "router", "sso"),
        ("zuultimate.access.router", "router", "access"),
        ("zuultimate.pos.router", "router", "pos"),
        ("zuultimate.crm.router", "router", "crm"),
        ("zuultimate.backup_resilience.router", "router", "backup"),
        ("zuultimate.plugins.router", "router", "plugins"),
    ]
    for mod_path, attr, label in _optional_routers:
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            v1.include_router(getattr(mod, attr))
        except ImportError:
            _log.info("Router %s not available (requires commercial license)", label)

    app.include_router(v1)

    return app
