"""Integration tests for tenant management endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers


async def test_create_tenant(integration_client):
    headers = await get_auth_headers(integration_client)
    resp = await integration_client.post(
        "/v1/tenants",
        json={"name": "Acme Corp", "slug": "acme"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Acme Corp"
    assert body["slug"] == "acme"
    assert body["is_active"] is True


async def test_create_duplicate_slug_fails(integration_client):
    headers = await get_auth_headers(integration_client)
    await integration_client.post(
        "/v1/tenants",
        json={"name": "Acme Corp", "slug": "acme"},
        headers=headers,
    )
    resp = await integration_client.post(
        "/v1/tenants",
        json={"name": "Other", "slug": "acme"},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_list_tenants(integration_client):
    headers = await get_auth_headers(integration_client)
    await integration_client.post(
        "/v1/tenants",
        json={"name": "Acme", "slug": "acme"},
        headers=headers,
    )
    await integration_client.post(
        "/v1/tenants",
        json={"name": "Beta", "slug": "beta"},
        headers=headers,
    )
    resp = await integration_client.get("/v1/tenants", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


async def test_get_tenant(integration_client):
    headers = await get_auth_headers(integration_client)
    create_resp = await integration_client.post(
        "/v1/tenants",
        json={"name": "Acme", "slug": "acme"},
        headers=headers,
    )
    tenant_id = create_resp.json()["id"]
    resp = await integration_client.get(f"/v1/tenants/{tenant_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["slug"] == "acme"


async def test_deactivate_tenant(integration_client):
    headers = await get_auth_headers(integration_client)
    create_resp = await integration_client.post(
        "/v1/tenants",
        json={"name": "Acme", "slug": "acme"},
        headers=headers,
    )
    tenant_id = create_resp.json()["id"]
    resp = await integration_client.post(
        f"/v1/tenants/{tenant_id}/deactivate", headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


async def test_tenant_requires_auth(integration_client):
    resp = await integration_client.get("/v1/tenants")
    assert resp.status_code in (401, 403)
