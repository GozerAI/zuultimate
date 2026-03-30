"""Integration tests for authentication flows and edge cases."""

import pytest

from tests.integration.conftest import get_auth_headers


# ── 1. Full register -> login -> access protected endpoint ──


async def test_register_login_access(integration_client):
    """Full flow: register a user, login, then access a protected endpoint."""
    client = integration_client

    # Register
    resp = await client.post(
        "/v1/identity/register",
        json={"email": "authflow@test.com", "username": "authflowuser", "password": "password123"},
    )
    assert resp.status_code == 200
    user = resp.json()
    user_id = user["id"]

    # Login
    resp = await client.post(
        "/v1/identity/login",
        json={"username": "authflowuser", "password": "password123"},
    )
    assert resp.status_code == 200
    tokens = resp.json()
    assert "access_token" in tokens
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # Access protected endpoint (get own user)
    resp = await client.get(f"/v1/identity/users/{user_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "authflowuser"


# ── 2. Duplicate email returns error ──


async def test_register_duplicate_email(integration_client):
    """Registering with the same email twice returns an error."""
    client = integration_client

    await client.post(
        "/v1/identity/register",
        json={"email": "dupemail@test.com", "username": "user_a", "password": "password123"},
    )
    resp = await client.post(
        "/v1/identity/register",
        json={"email": "dupemail@test.com", "username": "user_b", "password": "password123"},
    )
    assert resp.status_code in (409, 422)


# ── 3. Duplicate username returns error ──


async def test_register_duplicate_username(integration_client):
    """Registering with the same username twice returns an error."""
    client = integration_client

    await client.post(
        "/v1/identity/register",
        json={"email": "first@test.com", "username": "sameuser", "password": "password123"},
    )
    resp = await client.post(
        "/v1/identity/register",
        json={"email": "second@test.com", "username": "sameuser", "password": "password123"},
    )
    assert resp.status_code in (409, 422)


# ── 4. Login with wrong password ──


async def test_login_wrong_password(integration_client):
    """Login with incorrect password returns 401."""
    client = integration_client

    await client.post(
        "/v1/identity/register",
        json={"email": "wrongpw@test.com", "username": "wrongpwuser", "password": "password123"},
    )
    resp = await client.post(
        "/v1/identity/login",
        json={"username": "wrongpwuser", "password": "totallyWrong456"},
    )
    assert resp.status_code == 401


# ── 5. Login with nonexistent user ──


async def test_login_nonexistent_user(integration_client):
    """Login with a username that was never registered returns 401."""
    resp = await integration_client.post(
        "/v1/identity/login",
        json={"username": "ghost_user_xyz", "password": "password123"},
    )
    assert resp.status_code == 401


# ── 6. Access protected endpoint without token ──


async def test_access_without_token(integration_client):
    """Accessing a protected endpoint without Authorization header returns 401 or 403."""
    resp = await integration_client.get("/v1/identity/users/some-id")
    assert resp.status_code in (401, 403)


# ── 7. Access protected endpoint with invalid token ──


async def test_access_with_invalid_token(integration_client):
    """Accessing a protected endpoint with a garbage bearer token returns 401."""
    headers = {"Authorization": "Bearer this-is-not-a-valid-jwt-token"}
    resp = await integration_client.get("/v1/identity/users/some-id", headers=headers)
    assert resp.status_code == 401


# ── 8. Refresh token flow ──


async def test_refresh_token_flow(integration_client):
    """Login, then use the refresh token to obtain a new access token."""
    client = integration_client

    # Register + login
    await client.post(
        "/v1/identity/register",
        json={"email": "refresh@test.com", "username": "refreshuser", "password": "password123"},
    )
    resp = await client.post(
        "/v1/identity/login",
        json={"username": "refreshuser", "password": "password123"},
    )
    assert resp.status_code == 200
    tokens = resp.json()
    assert "refresh_token" in tokens

    # Use refresh token
    resp = await client.post(
        "/v1/identity/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens

    # New access token works on a protected endpoint
    new_headers = {"Authorization": f"Bearer {new_tokens['access_token']}"}
    resp = await client.get("/v1/identity/auth/validate", headers=new_headers)
    assert resp.status_code == 200


# ── 9. Health endpoint ──


async def test_health_endpoint(integration_client):
    """/health returns 200 with status ok."""
    resp = await integration_client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "timestamp" in body


# ── 10. CORS headers ──


async def test_cors_headers(integration_client):
    """OPTIONS preflight request from an allowed origin returns proper CORS headers."""
    resp = await integration_client.options(
        "/v1/identity/login",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"
