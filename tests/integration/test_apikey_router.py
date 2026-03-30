"""Integration tests for API key management endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers


async def _provision_tenant(client):
    """Provision a tenant with service token and return tenant_id + api_key."""
    settings = client._transport.app.state.settings
    settings.service_token = "test-service-token"
    resp = await client.post(
        "/v1/tenants/provision",
        json={
            "name": "Key Test Corp",
            "slug": "key-test",
            "owner_email": "owner@keytest.com",
            "owner_username": "keyowner",
            "owner_password": "Keypass123",
            "plan": "starter",
        },
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    return data["tenant_id"], data["api_key"]


async def _get_owner_headers(client):
    """Login as the provisioned tenant owner."""
    resp = await client.post(
        "/v1/identity/login",
        json={"username": "keyowner", "password": "Keypass123"},
    )
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ── Create ────────────────────────────────────────────────────────────────────


async def test_create_api_key(integration_client):
    tenant_id, _ = await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "Test Key"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Test Key"
    assert body["raw_key"].startswith("gzr_")
    assert body["is_active"] is True
    assert body["tenant_id"] == tenant_id
    assert body["key_prefix"] == body["raw_key"][:8]


async def test_create_api_key_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "Unauthorized"},
    )
    assert resp.status_code in (401, 403)


async def test_create_api_key_via_service_token(integration_client):
    tenant_id, _ = await _provision_tenant(integration_client)

    resp = await integration_client.post(
        f"/v1/api-keys/service/create?tenant_id={tenant_id}",
        json={"name": "Service Key"},
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["raw_key"].startswith("gzr_")
    assert body["name"] == "Service Key"


async def test_service_create_requires_tenant_id(integration_client):
    await _provision_tenant(integration_client)

    resp = await integration_client.post(
        "/v1/api-keys/service/create",
        json={"name": "No Tenant"},
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 400


# ── List ──────────────────────────────────────────────────────────────────────


async def test_list_api_keys(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    # Provisioning creates one "Default" key, add another
    await integration_client.post(
        "/v1/api-keys",
        json={"name": "Extra Key"},
        headers=headers,
    )

    resp = await integration_client.get("/v1/api-keys", headers=headers)
    assert resp.status_code == 200
    keys = resp.json()
    assert len(keys) >= 2
    names = {k["name"] for k in keys}
    assert "Default" in names
    assert "Extra Key" in names
    # raw_key should NOT be in list response
    for k in keys:
        assert "raw_key" not in k


# ── Revoke ────────────────────────────────────────────────────────────────────


async def test_revoke_api_key(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "To Revoke"},
        headers=headers,
    )
    key_id = create_resp.json()["id"]

    resp = await integration_client.post(
        f"/v1/api-keys/{key_id}/revoke",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


async def test_revoked_key_cannot_authenticate(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "Revoke Auth Test"},
        headers=headers,
    )
    raw_key = create_resp.json()["raw_key"]
    key_id = create_resp.json()["id"]

    # Key works before revocation
    resp = await integration_client.get(
        "/v1/api-keys",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 200

    # Revoke
    await integration_client.post(
        f"/v1/api-keys/{key_id}/revoke",
        headers=headers,
    )

    # Key no longer works
    resp = await integration_client.get(
        "/v1/api-keys",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 401


# ── Rotate ────────────────────────────────────────────────────────────────────


async def test_rotate_api_key(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "To Rotate"},
        headers=headers,
    )
    old_id = create_resp.json()["id"]
    old_key = create_resp.json()["raw_key"]

    resp = await integration_client.post(
        f"/v1/api-keys/{old_id}/rotate",
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["raw_key"].startswith("gzr_")
    assert body["raw_key"] != old_key
    assert body["name"] == "To Rotate"
    assert body["id"] != old_id  # New key has new ID


async def test_rotated_old_key_inactive(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "Rotate Check"},
        headers=headers,
    )
    old_id = create_resp.json()["id"]
    old_key = create_resp.json()["raw_key"]

    await integration_client.post(
        f"/v1/api-keys/{old_id}/rotate",
        headers=headers,
    )

    # Old key should be revoked
    resp = await integration_client.get(
        "/v1/api-keys",
        headers={"Authorization": f"Bearer {old_key}"},
    )
    assert resp.status_code == 401


# ── Delete ────────────────────────────────────────────────────────────────────


async def test_delete_api_key(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "To Delete"},
        headers=headers,
    )
    key_id = create_resp.json()["id"]

    resp = await integration_client.delete(
        f"/v1/api-keys/{key_id}",
        headers=headers,
    )
    assert resp.status_code == 200

    # Should be gone from list
    list_resp = await integration_client.get("/v1/api-keys", headers=headers)
    key_ids = {k["id"] for k in list_resp.json()}
    assert key_id not in key_ids


async def test_delete_nonexistent_key_404(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    resp = await integration_client.delete(
        "/v1/api-keys/nonexistent-id",
        headers=headers,
    )
    assert resp.status_code == 404


# ── Auth with created key ─────────────────────────────────────────────────────


async def test_created_key_authenticates(integration_client):
    await _provision_tenant(integration_client)
    headers = await _get_owner_headers(integration_client)

    create_resp = await integration_client.post(
        "/v1/api-keys",
        json={"name": "Auth Test Key"},
        headers=headers,
    )
    raw_key = create_resp.json()["raw_key"]

    # Use the new key to call an authenticated endpoint
    resp = await integration_client.get(
        "/v1/identity/auth/validate",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "apikey:Auth Test Key"
