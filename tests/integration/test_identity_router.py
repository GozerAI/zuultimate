"""Integration tests for identity router endpoints."""

import pytest

from tests.integration.conftest import get_auth_headers


async def test_register_login_get_refresh_logout(integration_client):
    """Full flow: register -> login -> get user -> refresh -> logout."""
    client = integration_client

    # Register
    resp = await client.post(
        "/v1/identity/register",
        json={"email": "flow@test.com", "username": "flowuser", "password": "password123"},
    )
    assert resp.status_code == 200
    user = resp.json()
    assert user["username"] == "flowuser"
    user_id = user["id"]

    # Login
    resp = await client.post(
        "/v1/identity/login",
        json={"username": "flowuser", "password": "password123"},
    )
    assert resp.status_code == 200
    token_data = resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # Get user (requires auth)
    resp = await client.get(f"/v1/identity/users/{user_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == "flow@test.com"

    # Refresh
    resp = await client.post(
        "/v1/identity/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens

    # Old access token should be revoked after refresh
    resp = await client.get(f"/v1/identity/users/{user_id}", headers=headers)
    assert resp.status_code == 401

    # New access token works
    new_headers = {"Authorization": f"Bearer {new_tokens['access_token']}"}
    resp = await client.get(f"/v1/identity/users/{user_id}", headers=new_headers)
    assert resp.status_code == 200

    # Logout
    resp = await client.post("/v1/identity/logout", headers=new_headers)
    assert resp.status_code == 200

    # Token no longer works after logout
    resp = await client.get(f"/v1/identity/users/{user_id}", headers=new_headers)
    assert resp.status_code == 401


async def test_register_duplicate(integration_client):
    await integration_client.post(
        "/v1/identity/register",
        json={"email": "dup@test.com", "username": "dupuser", "password": "password123"},
    )
    resp = await integration_client.post(
        "/v1/identity/register",
        json={"email": "dup@test.com", "username": "dupuser2", "password": "password123"},
    )
    assert resp.status_code == 422


async def test_login_bad_password(integration_client):
    await integration_client.post(
        "/v1/identity/register",
        json={"email": "bad@test.com", "username": "badpw", "password": "password123"},
    )
    resp = await integration_client.post(
        "/v1/identity/login",
        json={"username": "badpw", "password": "wrongpass"},
    )
    assert resp.status_code == 401


async def test_get_user_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "authuser")
    resp = await integration_client.get("/v1/identity/users/nonexistent", headers=headers)
    assert resp.status_code == 404


async def test_get_user_requires_auth(integration_client):
    resp = await integration_client.get("/v1/identity/users/some-id")
    assert resp.status_code in (401, 403)


async def test_invalid_email_rejected(integration_client):
    resp = await integration_client.post(
        "/v1/identity/register",
        json={"email": "not-an-email", "username": "user1", "password": "password123"},
    )
    assert resp.status_code == 422


async def test_weak_password_rejected(integration_client):
    resp = await integration_client.post(
        "/v1/identity/register",
        json={"email": "pw@test.com", "username": "user2", "password": "abcdefgh"},
    )
    assert resp.status_code == 422  # no digit


# ── MFA integration tests ──


async def test_mfa_setup_requires_auth(integration_client):
    """POST /v1/identity/mfa/setup without token returns 401."""
    resp = await integration_client.post("/v1/identity/mfa/setup")
    assert resp.status_code in (401, 403)


async def test_mfa_verify_requires_auth(integration_client):
    """POST /v1/identity/mfa/verify without token returns 401."""
    resp = await integration_client.post(
        "/v1/identity/mfa/verify",
        json={"code": "123456"},
    )
    assert resp.status_code in (401, 403)


async def test_mfa_challenge_invalid_token(integration_client):
    """POST /v1/identity/mfa/challenge with bad mfa_token returns 401/422."""
    resp = await integration_client.post(
        "/v1/identity/mfa/challenge",
        json={"mfa_token": "invalid-garbage-token", "code": "123456"},
    )
    # Bad JWT -> AuthenticationError (401) or pydantic validation (422)
    assert resp.status_code in (401, 422)
