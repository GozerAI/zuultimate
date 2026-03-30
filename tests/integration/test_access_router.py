"""Integration tests for access control router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_create_policy(integration_client):
    headers = await get_auth_headers(integration_client, "accessuser")
    resp = await integration_client.post(
        "/v1/access/policies",
        json={
            "name": "allow-all",
            "effect": "allow",
            "resource_pattern": "*",
            "action_pattern": "*",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "allow-all"
    assert "id" in data


async def test_create_policy_invalid_effect(integration_client):
    headers = await get_auth_headers(integration_client, "accessuser2")
    resp = await integration_client.post(
        "/v1/access/policies",
        json={
            "name": "bad",
            "effect": "maybe",
            "resource_pattern": "*",
            "action_pattern": "*",
        },
        headers=headers,
    )
    assert resp.status_code == 422


async def test_check_access_default_deny(integration_client):
    headers = await get_auth_headers(integration_client, "accessuser3")
    resp = await integration_client.post(
        "/v1/access/check",
        json={"user_id": "test-user", "resource": "vault/encrypt", "action": "execute"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is False


async def test_check_access_with_allow_policy(integration_client):
    headers = await get_auth_headers(integration_client, "accessuser4")
    await integration_client.post(
        "/v1/access/policies",
        json={
            "name": "allow-all",
            "effect": "allow",
            "resource_pattern": "*",
            "action_pattern": "*",
        },
        headers=headers,
    )
    resp = await integration_client.post(
        "/v1/access/check",
        json={"user_id": "test-user", "resource": "vault/encrypt", "action": "execute"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True


async def test_assign_role_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "accessuser5")
    resp = await integration_client.post(
        "/v1/access/roles/assign",
        json={"role_id": "nonexistent", "user_id": "user-1"},
        headers=headers,
    )
    assert resp.status_code == 404


async def test_access_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/access/policies",
        json={
            "name": "test",
            "effect": "allow",
            "resource_pattern": "*",
            "action_pattern": "*",
        },
    )
    assert resp.status_code in (401, 403)
