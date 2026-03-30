"""Prometheus metrics instrumentation for the identity platform."""

import time
from functools import wraps

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# -- Auth metrics --
AUTH_REQUESTS_TOTAL = Counter(
    "identity_auth_requests_total",
    "Total authentication requests",
    ["method", "status"],
)

AUTH_DURATION_SECONDS = Histogram(
    "identity_auth_duration_seconds",
    "Authentication request duration in seconds",
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# -- Token introspection --
TOKEN_INTROSPECT_TOTAL = Counter(
    "identity_token_introspect_total",
    "Total token introspection requests",
    ["status"],
)

# -- Risk decisions --
RISK_DECISIONS_TOTAL = Counter(
    "identity_risk_decisions_total",
    "Risk evaluation decisions",
    ["action"],
)

# -- DSAR --
DSAR_REQUESTS_TOTAL = Counter(
    "identity_dsar_requests_total",
    "DSAR requests",
    ["type", "status"],
)

# -- Consent --
CONSENT_OPERATIONS_TOTAL = Counter(
    "identity_consent_operations_total",
    "Consent grant/revoke operations",
    ["operation"],
)


def get_metrics_text() -> tuple[bytes, str]:
    """Return Prometheus metrics as (body, content_type)."""
    return generate_latest(), CONTENT_TYPE_LATEST
