"""Integration tests for CRM router endpoints."""

from unittest.mock import AsyncMock, patch

import httpx

from tests.integration.conftest import get_auth_headers

_FAKE_REQUEST = httpx.Request("GET", "https://test.com")


async def test_config_and_sync_flow(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser")
    resp = await integration_client.post(
        "/v1/crm/configs",
        json={"provider": "salesforce", "api_url": "https://sf.example.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    config = resp.json()
    assert config["provider"] == "salesforce"
    assert config["is_active"] is True

    # Start sync
    resp = await integration_client.post(
        "/v1/crm/sync", json={"config_id": config["id"]}, headers=headers,
    )
    assert resp.status_code == 200
    job = resp.json()
    assert job["status"] == "pending"

    # Get sync status
    resp = await integration_client.get(
        f"/v1/crm/sync/{job['id']}", headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["config_id"] == config["id"]


async def test_sync_nonexistent_config(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser2")
    resp = await integration_client.post(
        "/v1/crm/sync", json={"config_id": "nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_sync_status_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser3")
    resp = await integration_client.get(
        "/v1/crm/sync/nonexistent", headers=headers,
    )
    assert resp.status_code == 404


async def test_create_config_validation(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser4")
    resp = await integration_client.post(
        "/v1/crm/configs", json={"provider": ""}, headers=headers,
    )
    assert resp.status_code == 422


async def test_multiple_configs(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser5")
    resp1 = await integration_client.post(
        "/v1/crm/configs", json={"provider": "salesforce"}, headers=headers,
    )
    resp2 = await integration_client.post(
        "/v1/crm/configs", json={"provider": "hubspot"}, headers=headers,
    )
    assert resp1.json()["id"] != resp2.json()["id"]


async def test_crm_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/crm/configs", json={"provider": "test"},
    )
    assert resp.status_code in (401, 403)


async def test_list_adapters(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser_adapt1")
    resp = await integration_client.get("/v1/crm/adapters", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "adapters" in data
    adapters = data["adapters"]
    assert isinstance(adapters, list)
    assert "salesforce" in adapters
    assert "hubspot" in adapters
    assert "generic" in adapters


async def test_test_adapter(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser_adapt2")
    sf_response = httpx.Response(
        200, json={}, request=_FAKE_REQUEST,
    )
    with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=sf_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        resp = await integration_client.post(
            "/v1/crm/adapters/salesforce/test", headers=headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "connected" in data
    assert data["connected"] is True
    assert data["provider"] == "salesforce"


async def test_fetch_contacts(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser_adapt3")
    hs_response = httpx.Response(
        200,
        json={
            "results": [
                {"id": "101", "properties": {"firstname": "Alice", "lastname": "B", "email": "alice@hs.com"}},
                {"id": "102", "properties": {"firstname": "Bob", "lastname": "C", "email": "bob@hs.com"}},
            ],
        },
        request=_FAKE_REQUEST,
    )
    with patch("zuultimate.crm.adapters.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=hs_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        resp = await integration_client.post(
            "/v1/crm/adapters/hubspot/fetch", headers=headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "contacts" in data
    assert "count" in data
    assert isinstance(data["contacts"], list)
    assert data["count"] > 0
    # Verify contact structure from HubSpot adapter
    contact = data["contacts"][0]
    assert "vid" in contact
    assert "email" in contact
