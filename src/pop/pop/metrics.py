"""Prometheus metrics for Point-of-Presence proxy."""

from prometheus_client import Counter, Histogram, Gauge

pop_auth_total = Counter(
    "pop_auth_total",
    "Total PoP authentication attempts",
    ["status", "region"],
)

pop_cert_validations_total = Counter(
    "pop_cert_validations_total",
    "Total certificate validations",
    ["result"],  # valid, expired, revoked, invalid_chain
)

pop_posture_checks_total = Counter(
    "pop_posture_checks_total",
    "Total device posture checks",
    ["result"],  # pass, fail, step_up
)

pop_request_duration_seconds = Histogram(
    "pop_request_duration_seconds",
    "PoP request processing time",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

crl_age_seconds = Gauge(
    "crl_age_seconds",
    "Age of the cached CRL in seconds",
    ["region"],
)
