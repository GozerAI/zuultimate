"""Request middleware for correlation IDs and access logging."""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from zuultimate.common.logging import get_logger, request_id_var

_log = get_logger("zuultimate.http")


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds a configured threshold."""

    def __init__(self, app, max_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            return Response(
                content='{"error":"Request body too large","code":"PAYLOAD_TOO_LARGE"}',
                status_code=413,
                media_type="application/json",
            )
        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to each request and log request lifecycle."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        token = request_id_var.set(req_id)
        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            _log.error(
                "%s %s -> 500 (%.1fms)",
                request.method,
                request.url.path,
                duration_ms,
            )
            raise
        else:
            duration_ms = (time.perf_counter() - start) * 1000
            _log.info(
                "%s %s -> %d (%.1fms)",
                request.method,
                request.url.path,
                response.status_code,
                duration_ms,
            )
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_var.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to every response."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


class NamespaceMiddleware(BaseHTTPMiddleware):
    """Enforce namespace isolation between workforce and consumer routes.

    Workforce routes (/v1/workforce/*) require namespace=workforce in JWT.
    Consumer routes require namespace=consumer (or absent, defaulting to consumer).
    Exempt paths bypass namespace checks entirely.
    """

    _EXEMPT_PREFIXES = (
        "/health",
        "/metrics",
        "/.well-known/",
        "/v1/identity/auth/",
    )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Exempt paths pass through
        if any(path.startswith(p) for p in self._EXEMPT_PREFIXES):
            return await call_next(request)

        # Only check namespace on workforce or consumer API routes
        is_workforce_route = path.startswith("/v1/workforce")
        is_consumer_route = path.startswith("/v1/") and not is_workforce_route and not path.startswith("/v1/admin")

        if not is_workforce_route and not is_consumer_route:
            return await call_next(request)

        # Extract namespace from JWT (decode without verification)
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return await call_next(request)

        token = auth[7:]
        if token.startswith("gzr_"):
            # API keys don't carry namespace; pass through
            return await call_next(request)

        try:
            import jwt as pyjwt
            unverified = pyjwt.decode(token, options={"verify_signature": False})
        except Exception:
            return await call_next(request)

        namespace = unverified.get("namespace", "consumer")

        if is_workforce_route and namespace != "workforce":
            return Response(
                content='{"error":"Workforce namespace required","code":"NAMESPACE_FORBIDDEN"}',
                status_code=403,
                media_type="application/json",
            )

        if is_consumer_route and namespace != "consumer":
            return Response(
                content='{"error":"Consumer namespace required","code":"NAMESPACE_FORBIDDEN"}',
                status_code=403,
                media_type="application/json",
            )

        return await call_next(request)


class RegionRoutingMiddleware(BaseHTTPMiddleware):
    """Redirect requests to the correct region based on tenant's home_region.

    Only acts on authenticated JWT requests. API key requests, unauthenticated
    requests, and exempt paths pass through without a redirect.
    """

    def __init__(self, app, region: str = "us"):
        super().__init__(app)
        self.region = region
        self._exempt_prefixes = (
            "/health",
            "/metrics",
            "/.well-known/jwks.json",
            "/v1/identity/auth",
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Exempt paths always pass through
        if any(path.startswith(p) for p in self._exempt_prefixes):
            return await call_next(request)

        # Only inspect Bearer JWT tokens — not API keys (gzr_ prefix)
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and not auth[7:].startswith("gzr_"):
            try:
                import jwt
                token = auth[7:]
                unverified = jwt.decode(token, options={"verify_signature": False})
                tenant_id = unverified.get("tenant_id")
                if tenant_id:
                    db = request.app.state.db
                    from zuultimate.identity.models import Tenant
                    from sqlalchemy import select
                    async with db.get_session("identity") as session:
                        result = await session.execute(
                            select(Tenant.home_region).where(Tenant.id == tenant_id)
                        )
                        row = result.first()
                        if row and row[0] != self.region:
                            return Response(
                                status_code=307,
                                headers={
                                    "Location": f"https://zuultimate-{row[0]}.gozerai.com{path}",
                                },
                            )
            except Exception:
                pass

        return await call_next(request)
