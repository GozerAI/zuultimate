"""Integration tests for retention and compliance endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers

pytestmark = pytest.mark.asyncio


async def _get_auth_token(client):
    await client.post("/v1/identity/register", json={
        "email": "retention@test.com", "username": "retentionuser",
        "password": "TestPass123!", "display_name": "Retention Test"
    })
    resp = await client.post("/v1/identity/login", json={
        "username": "retentionuser", "password": "TestPass123!"
    })
    return resp.json()["access_token"]


async def test_retention_stats(integration_client):
    token = await _get_auth_token(integration_client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = await integration_client.get("/v1/ai/retention/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data
    assert "expired_events" in data
    assert "retention_days" in data
    assert "cutoff_date" in data


async def test_retention_archive(integration_client):
    token = await _get_auth_token(integration_client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = await integration_client.post("/v1/ai/retention/archive", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "archived_count" in data
    assert "events" in data
    assert isinstance(data["events"], list)


async def test_retention_purge(integration_client):
    token = await _get_auth_token(integration_client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = await integration_client.post("/v1/ai/retention/purge", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "purged" in data
    assert "retention_days" in data


async def test_compliance_report(integration_client):
    token = await _get_auth_token(integration_client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = await integration_client.get("/v1/ai/compliance/report", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Top-level fields
    assert "generated_at" in data
    assert "period" in data
    assert "summary" in data
    assert "by_type" in data
    assert "by_severity" in data
    assert "threat_analysis" in data
    assert "agent_activity" in data
    assert "policy_violations" in data
    # Nested summary fields
    assert "total_events" in data["summary"]
    # Nested period fields
    assert "start" in data["period"]
    assert "end" in data["period"]
    # Nested threat_analysis fields
    assert "total_threats" in data["threat_analysis"]
    assert "avg_threat_score" in data["threat_analysis"]
