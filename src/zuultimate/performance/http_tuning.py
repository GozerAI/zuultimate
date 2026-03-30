"""HTTP keep-alive tuning and request rate shaping.

Items:
- #197: HTTP keep-alive tuning
- #211: Request rate shaping for downstream protection
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.http_tuning")


# ─────────────────────────────────────────────────────────────────────────────
# #197  HTTP keep-alive tuning
# ─────────────────────────────────────────────────────────────────────────────

class KeepAliveMiddleware(BaseHTTPMiddleware):
    """Add keep-alive headers to responses for connection reuse.

    Configures server-side keep-alive timeout and max requests per connection.
    Works with Uvicorn's keep-alive support (``--timeout-keep-alive``).
    """

    def __init__(
        self,
        app,
        *,
        timeout: int = 75,
        max_requests: int = 1000,
    ):
        super().__init__(app)
        self._timeout = timeout
        self._max_requests = max_requests
        self._connection_counts: dict[str, int] = defaultdict(int)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Set keep-alive parameters
        response.headers["Connection"] = "keep-alive"
        response.headers["Keep-Alive"] = (
            f"timeout={self._timeout}, max={self._max_requests}"
        )

        return response


def get_uvicorn_keepalive_config(
    *,
    timeout_keep_alive: int = 75,
    limit_max_requests: int | None = None,
) -> dict[str, Any]:
    """Return Uvicorn config dict for optimal keep-alive behavior.

    Pass these as kwargs to ``uvicorn.run()`` or include in uvicorn config.
    """
    config: dict[str, Any] = {
        "timeout_keep_alive": timeout_keep_alive,
        # HTTP/1.1 pipelining support
        "http": "h11",
    }
    if limit_max_requests is not None:
        config["limit_max_requests"] = limit_max_requests
    return config


# ─────────────────────────────────────────────────────────────────────────────
# #211  Request rate shaping for downstream protection
# ─────────────────────────────────────────────────────────────────────────────

class RateShaper:
    """Token-bucket rate shaper that smooths bursty traffic to downstream services.

    Unlike a rate *limiter* (which rejects), a rate *shaper* delays requests
    to stay within the configured throughput budget.  Requests that would
    exceed the burst capacity are rejected with 503.
    """

    def __init__(
        self,
        *,
        rate_per_second: float = 100.0,
        burst_size: int = 50,
    ):
        self._rate = rate_per_second
        self._burst = burst_size
        self._tokens = float(burst_size)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._shaped = 0
        self._rejected = 0

    async def acquire(self, timeout: float = 1.0) -> bool:
        """Try to acquire a token, waiting up to ``timeout`` seconds.

        Returns True if the request may proceed, False if it should be rejected.
        """
        async with self._lock:
            self._refill()

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True

            # Calculate wait time for next token
            wait = (1.0 - self._tokens) / self._rate
            if wait > timeout:
                self._rejected += 1
                return False

        # Wait outside the lock
        await asyncio.sleep(wait)
        self._shaped += 1

        async with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            self._rejected += 1
            return False

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "rate_per_second": self._rate,
            "burst_size": self._burst,
            "current_tokens": round(self._tokens, 2),
            "shaped_requests": self._shaped,
            "rejected_requests": self._rejected,
        }


class RateShapingMiddleware(BaseHTTPMiddleware):
    """Middleware that applies rate shaping to all or selected routes.

    Requests that exceed the shaped rate are delayed; those that exceed
    the burst are rejected with 503 Service Unavailable.
    """

    def __init__(
        self,
        app,
        *,
        shaper: RateShaper | None = None,
        protected_prefixes: list[str] | None = None,
    ):
        super().__init__(app)
        self._shaper = shaper or RateShaper()
        self._protected_prefixes = protected_prefixes or ["/v1/"]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Only shape protected routes
        if not any(path.startswith(p) for p in self._protected_prefixes):
            return await call_next(request)

        allowed = await self._shaper.acquire()
        if not allowed:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service temporarily at capacity",
                    "code": "RATE_SHAPED",
                    "retry_after": 1,
                },
                headers={"Retry-After": "1"},
            )

        return await call_next(request)
