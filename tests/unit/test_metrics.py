"""Tests for Prometheus metrics instrumentation."""

import pytest
from httpx import ASGITransport, AsyncClient

from zuultimate.common.metrics import (
    AUTH_DURATION_SECONDS,
    AUTH_REQUESTS_TOTAL,
    CONSENT_OPERATIONS_TOTAL,
    DSAR_REQUESTS_TOTAL,
    RISK_DECISIONS_TOTAL,
    TOKEN_INTROSPECT_TOTAL,
    get_metrics_text,
)


class TestAuthCounter:
    """Verify authentication counter increments appear in Prometheus output."""

    def test_auth_counter_increments(self):
        AUTH_REQUESTS_TOTAL.labels(method="password", status="success").inc()
        body, content_type = get_metrics_text()
        text = body.decode()
        assert "identity_auth_requests_total" in text
        assert 'method="password"' in text
        assert 'status="success"' in text


class TestAuthHistogram:
    """Verify authentication histogram observations appear in output."""

    def test_auth_histogram_observes(self):
        AUTH_DURATION_SECONDS.observe(0.123)
        body, _ = get_metrics_text()
        text = body.decode()
        assert "identity_auth_duration_seconds_bucket" in text
        assert "identity_auth_duration_seconds_count" in text
        assert "identity_auth_duration_seconds_sum" in text


class TestRiskCounter:
    """Verify risk decision counter appears in Prometheus output."""

    def test_risk_counter(self):
        RISK_DECISIONS_TOTAL.labels(action="allow").inc()
        body, _ = get_metrics_text()
        text = body.decode()
        assert "identity_risk_decisions_total" in text
        assert 'action="allow"' in text


class TestTokenIntrospectCounter:
    """Verify token introspection counter appears in output."""

    def test_token_introspect_counter(self):
        TOKEN_INTROSPECT_TOTAL.labels(status="active").inc()
        body, _ = get_metrics_text()
        text = body.decode()
        assert "identity_token_introspect_total" in text
        assert 'status="active"' in text


class TestDSARCounter:
    """Verify DSAR request counter appears in output."""

    def test_dsar_counter(self):
        DSAR_REQUESTS_TOTAL.labels(type="access", status="submitted").inc()
        body, _ = get_metrics_text()
        text = body.decode()
        assert "identity_dsar_requests_total" in text
        assert 'type="access"' in text


class TestConsentCounter:
    """Verify consent operations counter appears in output."""

    def test_consent_counter(self):
        CONSENT_OPERATIONS_TOTAL.labels(operation="grant").inc()
        body, _ = get_metrics_text()
        text = body.decode()
        assert "identity_consent_operations_total" in text
        assert 'operation="grant"' in text


class TestGetMetricsText:
    """Verify get_metrics_text returns valid Prometheus format."""

    def test_returns_bytes_and_content_type(self):
        body, content_type = get_metrics_text()
        assert isinstance(body, bytes)
        assert "text/plain" in content_type or "openmetrics" in content_type

    def test_contains_help_lines(self):
        body, _ = get_metrics_text()
        text = body.decode()
        assert "# HELP identity_auth_requests_total" in text
        assert "# TYPE identity_auth_requests_total counter" in text


class TestMetricsEndpoint:
    """Verify the /metrics HTTP endpoint returns Prometheus format."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_prometheus_format(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"] or "openmetrics" in resp.headers["content-type"]
        assert "identity_auth_requests_total" in resp.text
