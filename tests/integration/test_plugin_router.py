"""Integration tests for plugin management endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers

pytestmark = pytest.mark.asyncio


async def test_requires_auth(integration_client):
    """GET /v1/plugins/ without auth returns 403."""
    resp = await integration_client.get("/v1/plugins/")
    assert resp.status_code in (401, 403)


async def test_list_plugins_empty(integration_client):
    """GET /v1/plugins/ with auth returns empty list when no plugins registered."""
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.get("/v1/plugins/", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_plugin_not_found(integration_client):
    """GET /v1/plugins/nonexistent returns 404."""
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.get("/v1/plugins/nonexistent", headers=headers)
    assert resp.status_code == 404


async def test_register_returns_501(integration_client):
    """POST /v1/plugins/register returns 501 (not supported via API)."""
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.post(
        "/v1/plugins/register",
        json={"name": "test-plugin", "version": "1.0.0", "description": "A test plugin"},
        headers=headers,
    )
    assert resp.status_code == 501
    body = resp.json()
    assert "not supported" in body["detail"].lower()


async def test_webhook_not_found(integration_client):
    """POST /v1/plugins/nonexistent/webhook returns 404."""
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.post(
        "/v1/plugins/nonexistent/webhook",
        json={"event": "test"},
        headers=headers,
    )
    assert resp.status_code == 404
