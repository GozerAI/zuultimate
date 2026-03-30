"""API response caching with Vary headers.

Item #85: API response caching with Vary headers.

Provides a decorator and middleware for caching API responses with proper
HTTP cache control.  Uses Vary headers to ensure cached responses are
correctly keyed by authorization, content-type, etc.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from zuultimate.common.logging import get_logger
from zuultimate.performance.caching import TTLCache

_log = get_logger("zuultimate.performance.response_caching")


class ResponseCache:
    """In-process API response cache with Vary-header awareness.

    Caches JSON responses keyed by path + selected request headers (those
    listed in the Vary header).  Only caches successful (2xx) GET responses.
    """

    def __init__(self, *, ttl: float = 30.0, max_size: int = 1024):
        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)
        self._vary_headers: list[str] = ["Authorization", "Accept"]

    def _cache_key(self, request: Request) -> str:
        parts = [request.method, request.url.path, str(request.query_params)]
        for header in self._vary_headers:
            parts.append(request.headers.get(header, ""))
        raw = "|".join(parts)
        return f"resp:{hashlib.sha256(raw.encode()).hexdigest()[:32]}"

    def get(self, request: Request) -> dict[str, Any] | None:
        """Retrieve cached response if available."""
        if request.method != "GET":
            return None
        return self._cache.get(self._cache_key(request))

    def put(self, request: Request, status_code: int, body: Any, ttl: float | None = None) -> None:
        """Cache a response.  Only caches 2xx GET responses."""
        if request.method != "GET" or status_code < 200 or status_code >= 300:
            return
        self._cache.put(
            self._cache_key(request),
            {"status_code": status_code, "body": body},
            ttl=ttl,
        )

    def invalidate_path(self, path: str) -> int:
        """Invalidate all cached responses for a given path prefix."""
        return self._cache.invalidate_prefix(f"resp:")

    @property
    def vary_headers(self) -> list[str]:
        return list(self._vary_headers)

    @vary_headers.setter
    def vary_headers(self, headers: list[str]) -> None:
        self._vary_headers = headers

    @property
    def stats(self) -> dict[str, int]:
        return self._cache.stats


class ResponseCacheMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that adds cache-control and Vary headers.

    This does not do full response caching (that's handled by ResponseCache
    at the service level), but ensures proper HTTP headers are set so
    downstream proxies/CDNs can cache effectively.
    """

    def __init__(
        self,
        app,
        *,
        max_age: int = 0,
        vary_headers: list[str] | None = None,
        cacheable_prefixes: list[str] | None = None,
    ):
        super().__init__(app)
        self._max_age = max_age
        self._vary = ", ".join(vary_headers or ["Authorization", "Accept"])
        self._cacheable_prefixes = cacheable_prefixes or []

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Always set Vary header
        response.headers["Vary"] = self._vary

        # Set Cache-Control for cacheable paths
        path = request.url.path
        if request.method == "GET" and any(path.startswith(p) for p in self._cacheable_prefixes):
            response.headers["Cache-Control"] = f"public, max-age={self._max_age}"
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

        return response
