"""Integration tests for health, liveness, and readiness probes."""

import pytest


async def test_health_returns_ok_with_checks(integration_client):
    resp = await integration_client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] is not None
    assert body["timestamp"] is not None
    # Should have per-DB checks
    checks = body["checks"]
    assert isinstance(checks, dict)
    for key, val in checks.items():
        if key == "redis":
            assert val in ("ok", "unavailable (fallback)")
        else:
            assert val == "ok"


async def test_health_includes_all_db_keys(integration_client):
    resp = await integration_client.get("/health")
    checks = resp.json()["checks"]
    expected_keys = {"identity", "credential", "session", "transaction", "audit", "crm", "redis"}
    assert set(checks.keys()) == expected_keys


async def test_liveness_always_200(integration_client):
    resp = await integration_client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


async def test_readiness_returns_ready(integration_client):
    resp = await integration_client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


async def test_request_id_header_present(integration_client):
    resp = await integration_client.get("/health")
    assert "x-request-id" in resp.headers


async def test_request_id_echo(integration_client):
    resp = await integration_client.get(
        "/health", headers={"X-Request-ID": "trace-123"}
    )
    assert resp.headers["x-request-id"] == "trace-123"
