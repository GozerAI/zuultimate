"""Integration tests for webhook management endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers


async def test_create_webhook(integration_client):
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.post(
        "/v1/webhooks",
        json={
            "url": "https://example.com/hook",
            "events_filter": "security.*",
            "description": "Security alerts",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["url"] == "https://example.com/hook"
    assert body["is_active"] is True


async def test_list_webhooks(integration_client):
    headers = await get_auth_headers(integration_client)
    await integration_client.post(
        "/v1/webhooks",
        json={"url": "https://a.com/hook"},
        headers=headers,
    )
    await integration_client.post(
        "/v1/webhooks",
        json={"url": "https://b.com/hook"},
        headers=headers,
    )
    resp = await integration_client.get("/v1/webhooks", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


async def test_delete_webhook(integration_client):
    headers = await get_auth_headers(integration_client)
    create_resp = await integration_client.post(
        "/v1/webhooks",
        json={"url": "https://a.com/hook"},
        headers=headers,
    )
    webhook_id = create_resp.json()["id"]
    resp = await integration_client.delete(
        f"/v1/webhooks/{webhook_id}", headers=headers
    )
    assert resp.status_code == 200

    # Should no longer appear in list
    list_resp = await integration_client.get("/v1/webhooks", headers=headers)
    assert len(list_resp.json()) == 0


async def test_webhook_requires_auth(integration_client):
    resp = await integration_client.get("/v1/webhooks")
    assert resp.status_code in (401, 403)
