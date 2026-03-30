"""Integration tests for SSO router endpoints."""

from unittest.mock import AsyncMock, patch

import httpx

from tests.integration.conftest import get_auth_headers

_FAKE_REQUEST = httpx.Request("POST", "https://test.com/token")


async def test_create_and_list_providers(integration_client):
    headers = await get_auth_headers(integration_client, "ssouser")
    resp = await integration_client.post(
        "/v1/sso/providers",
        json={
            "name": "Google",
            "protocol": "oidc",
            "issuer_url": "https://accounts.google.com",
            "client_id": "client-123",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    provider = resp.json()
    assert provider["name"] == "Google"

    resp = await integration_client.get("/v1/sso/providers", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_initiate_login(integration_client):
    headers = await get_auth_headers(integration_client, "ssouser2")
    resp = await integration_client.post(
        "/v1/sso/providers",
        json={
            "name": "Okta",
            "protocol": "oidc",
            "issuer_url": "https://okta.example.com",
            "client_id": "okta-client",
        },
        headers=headers,
    )
    provider_id = resp.json()["id"]

    resp = await integration_client.get(f"/v1/sso/login/{provider_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert "redirect_url" in data
    assert "state" in data
    assert "nonce" in data
    assert "code_challenge" in data["redirect_url"]


async def test_sso_callback(integration_client):
    headers = await get_auth_headers(integration_client, "ssouser3")
    resp = await integration_client.post(
        "/v1/sso/providers",
        json={
            "name": "Auth0",
            "protocol": "oidc",
            "issuer_url": "https://auth0.example.com",
            "client_id": "auth0-client",
        },
        headers=headers,
    )
    provider_id = resp.json()["id"]

    # Initiate login to get valid state and nonce
    resp = await integration_client.get(f"/v1/sso/login/{provider_id}")
    assert resp.status_code == 200
    login_data = resp.json()
    state = login_data["state"]
    nonce = login_data["nonce"]

    token_response = httpx.Response(
        200,
        json={
            "access_token": "idp-access-token",
            "token_type": "Bearer",
            "email": "sso-user@auth0.com",
            "preferred_username": "sso-user",
            "name": "SSO User",
        },
        request=_FAKE_REQUEST,
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        resp = await integration_client.post(
            "/v1/sso/callback",
            json={
                "provider_id": provider_id,
                "code": "authcode123",
                "state": state,
                "nonce": nonce,
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["sso_provider"] == "Auth0"


async def test_sso_requires_auth_for_management(integration_client):
    resp = await integration_client.post(
        "/v1/sso/providers",
        json={
            "name": "Google",
            "protocol": "oidc",
            "issuer_url": "https://google.com",
            "client_id": "c1",
        },
    )
    assert resp.status_code in (401, 403)


async def test_deactivate_provider(integration_client):
    headers = await get_auth_headers(integration_client, "ssouser4")
    resp = await integration_client.post(
        "/v1/sso/providers",
        json={
            "name": "Tmp",
            "protocol": "oidc",
            "issuer_url": "https://tmp.com",
            "client_id": "c1",
        },
        headers=headers,
    )
    provider_id = resp.json()["id"]

    resp = await integration_client.delete(
        f"/v1/sso/providers/{provider_id}", headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False
