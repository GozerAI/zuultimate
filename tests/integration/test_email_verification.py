"""Integration tests for email verification endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_send_and_confirm_verification(integration_client):
    headers = await get_auth_headers(integration_client, "emailuser")

    # Send verification
    resp = await integration_client.post("/v1/identity/verify-email/send", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["email"] == "emailuser@test.com"

    # Confirm verification
    resp = await integration_client.post(
        "/v1/identity/verify-email/confirm",
        json={"token": data["token"]},
    )
    assert resp.status_code == 200
    assert resp.json()["verified"] is True


async def test_confirm_invalid_token(integration_client):
    resp = await integration_client.post(
        "/v1/identity/verify-email/confirm",
        json={"token": "bad-token"},
    )
    assert resp.status_code == 422


async def test_send_requires_auth(integration_client):
    resp = await integration_client.post("/v1/identity/verify-email/send")
    assert resp.status_code in (401, 403)


async def test_double_verify_fails(integration_client):
    headers = await get_auth_headers(integration_client, "emailuser2")
    resp = await integration_client.post("/v1/identity/verify-email/send", headers=headers)
    token = resp.json()["token"]

    await integration_client.post(
        "/v1/identity/verify-email/confirm", json={"token": token}
    )

    # Second send should fail (already verified)
    resp = await integration_client.post("/v1/identity/verify-email/send", headers=headers)
    assert resp.status_code == 422
