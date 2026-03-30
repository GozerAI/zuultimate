"""API response SLA tracking per endpoint.

Item #92: API response SLA tracking per endpoint.

Tracks response time percentiles per endpoint and reports SLA compliance.
Designed to be wired as middleware.
"""

from __future__ import annotations

import bisect
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.sla_tracking")


class EndpointSLATracker:
    """Track response time distributions per endpoint for SLA reporting.

    Maintains a sorted list of recent latencies per endpoint (capped at
    ``window_size``) and computes percentiles on demand.
    """

    def __init__(
        self,
        *,
        window_size: int = 1000,
        sla_target_ms: float = 500.0,
    ):
        self._window_size = window_size
        self._sla_target_ms = sla_target_ms
        self._latencies: dict[str, list[float]] = defaultdict(list)
        self._total_requests: dict[str, int] = defaultdict(int)
        self._sla_violations: dict[str, int] = defaultdict(int)

    def record(self, endpoint: str, latency_ms: float) -> None:
        """Record a request latency for an endpoint."""
        self._total_requests[endpoint] += 1
        latencies = self._latencies[endpoint]
        bisect.insort(latencies, latency_ms)
        if len(latencies) > self._window_size:
            latencies.pop(0)
        if latency_ms > self._sla_target_ms:
            self._sla_violations[endpoint] += 1

    def percentile(self, endpoint: str, p: float) -> float | None:
        """Return the p-th percentile latency (0-100) for an endpoint."""
        latencies = self._latencies.get(endpoint)
        if not latencies:
            return None
        idx = int(len(latencies) * p / 100)
        idx = min(idx, len(latencies) - 1)
        return latencies[idx]

    def sla_compliance(self, endpoint: str) -> float | None:
        """Return SLA compliance percentage for an endpoint (0-100)."""
        total = self._total_requests.get(endpoint, 0)
        if total == 0:
            return None
        violations = self._sla_violations.get(endpoint, 0)
        return round((1 - violations / total) * 100, 2)

    def summary(self, endpoint: str | None = None) -> dict[str, Any]:
        """Return SLA summary for one or all endpoints."""
        if endpoint:
            return self._endpoint_summary(endpoint)
        return {
            ep: self._endpoint_summary(ep)
            for ep in sorted(self._total_requests.keys())
        }

    def _endpoint_summary(self, endpoint: str) -> dict[str, Any]:
        return {
            "total_requests": self._total_requests.get(endpoint, 0),
            "sla_target_ms": self._sla_target_ms,
            "sla_compliance_pct": self.sla_compliance(endpoint),
            "p50_ms": self.percentile(endpoint, 50),
            "p95_ms": self.percentile(endpoint, 95),
            "p99_ms": self.percentile(endpoint, 99),
            "violations": self._sla_violations.get(endpoint, 0),
        }


class SLATrackingMiddleware(BaseHTTPMiddleware):
    """Middleware that records request latency into an EndpointSLATracker."""

    def __init__(self, app, *, tracker: EndpointSLATracker | None = None):
        super().__init__(app)
        self.tracker = tracker or EndpointSLATracker()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Use method + path as endpoint key
        endpoint = f"{request.method} {request.url.path}"
        self.tracker.record(endpoint, elapsed_ms)

        # Add server timing header
        response.headers["Server-Timing"] = f"total;dur={elapsed_ms:.1f}"
        return response
