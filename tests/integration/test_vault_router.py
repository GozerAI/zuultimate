"""Integration tests for vault router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_encrypt_decrypt_roundtrip(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser")
    resp = await integration_client.post(
        "/v1/vault/encrypt",
        json={"plaintext": "top secret", "label": "test", "owner_id": "u1"},
        headers=headers,
    )
    assert resp.status_code == 200
    blob_id = resp.json()["blob_id"]

    resp = await integration_client.post(
        "/v1/vault/decrypt", json={"blob_id": blob_id}, headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["plaintext"] == "top secret"


async def test_decrypt_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser2")
    resp = await integration_client.post(
        "/v1/vault/decrypt", json={"blob_id": "nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_tokenize_detokenize_roundtrip(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser3")
    resp = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "4111111111111111"}, headers=headers,
    )
    assert resp.status_code == 200
    token = resp.json()["token"]
    assert token.startswith("tok_")

    resp = await integration_client.post(
        "/v1/vault/detokenize", json={"token": token}, headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "4111111111111111"


async def test_tokenize_idempotent(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser4")
    resp1 = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "same"}, headers=headers,
    )
    resp2 = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "same"}, headers=headers,
    )
    assert resp1.json()["token"] == resp2.json()["token"]


async def test_detokenize_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser5")
    resp = await integration_client.post(
        "/v1/vault/detokenize", json={"token": "tok_nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_encrypt_empty_plaintext(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser6")
    resp = await integration_client.post(
        "/v1/vault/encrypt", json={"plaintext": ""}, headers=headers,
    )
    assert resp.status_code == 422


async def test_vault_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/vault/encrypt", json={"plaintext": "secret"},
    )
    assert resp.status_code in (401, 403)


# ── Password Vault (user-scoped secrets) ──


async def test_store_secret(integration_client):
    """POST /v1/vault/secrets with auth — verify 200 and returned id."""
    headers = await get_auth_headers(integration_client, "secretuser")

    resp = await integration_client.post(
        "/v1/vault/secrets",
        json={
            "name": "my-api-key",
            "value": "sk-abc123xyz",
            "category": "api_key",
            "notes": "production API key",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert data["name"] == "my-api-key"
    assert data["category"] == "api_key"


async def test_list_secrets(integration_client):
    """Store a secret, GET /v1/vault/secrets, verify it appears in list."""
    headers = await get_auth_headers(integration_client, "listuser")

    # Store a secret first
    resp = await integration_client.post(
        "/v1/vault/secrets",
        json={"name": "list-test-secret", "value": "hidden-value"},
        headers=headers,
    )
    assert resp.status_code == 200

    # List secrets
    resp = await integration_client.get("/v1/vault/secrets", headers=headers)
    assert resp.status_code == 200
    secrets = resp.json()
    assert isinstance(secrets, list)
    assert len(secrets) >= 1
    names = [s["name"] for s in secrets]
    assert "list-test-secret" in names
    # List should NOT contain decrypted values
    for s in secrets:
        assert "value" not in s


async def test_get_secret(integration_client):
    """Store a secret, GET /v1/vault/secrets/{id}, verify decrypted value returned."""
    headers = await get_auth_headers(integration_client, "getuser")

    # Store
    resp = await integration_client.post(
        "/v1/vault/secrets",
        json={"name": "get-test-secret", "value": "my-password-123"},
        headers=headers,
    )
    assert resp.status_code == 200
    secret_id = resp.json()["id"]

    # Get by ID — should return decrypted value
    resp = await integration_client.get(
        f"/v1/vault/secrets/{secret_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == secret_id
    assert data["name"] == "get-test-secret"
    assert data["value"] == "my-password-123"


async def test_delete_secret(integration_client):
    """Store a secret, DELETE /v1/vault/secrets/{id}, verify deleted."""
    headers = await get_auth_headers(integration_client, "deluser")

    # Store
    resp = await integration_client.post(
        "/v1/vault/secrets",
        json={"name": "delete-me", "value": "ephemeral"},
        headers=headers,
    )
    assert resp.status_code == 200
    secret_id = resp.json()["id"]

    # Delete
    resp = await integration_client.delete(
        f"/v1/vault/secrets/{secret_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    # Verify it is gone
    resp = await integration_client.get(
        f"/v1/vault/secrets/{secret_id}",
        headers=headers,
    )
    assert resp.status_code == 404


async def test_store_secret_validation(integration_client):
    """POST /v1/vault/secrets with empty name — verify 422."""
    headers = await get_auth_headers(integration_client, "valuser")

    resp = await integration_client.post(
        "/v1/vault/secrets",
        json={"name": "", "value": "some-value"},
        headers=headers,
    )
    # Pydantic Field(min_length=1) rejects empty string with 422
    assert resp.status_code == 422


# ── Vault Rotation ──


async def test_rotate_blob(integration_client):
    """Encrypt something, POST /v1/vault/rotate/{blob_id}, verify success."""
    headers = await get_auth_headers(integration_client, "rotateuser")

    # Encrypt a blob first
    resp = await integration_client.post(
        "/v1/vault/encrypt",
        json={"plaintext": "rotate-me-data", "label": "rotate-test"},
        headers=headers,
    )
    assert resp.status_code == 200
    blob_id = resp.json()["blob_id"]

    # Rotate
    resp = await integration_client.post(
        f"/v1/vault/rotate/{blob_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["blob_id"] == blob_id
    assert data["rotation_count"] == 1
    assert "last_rotated" in data

    # Verify decryption still works after rotation
    resp = await integration_client.post(
        "/v1/vault/decrypt",
        json={"blob_id": blob_id},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["plaintext"] == "rotate-me-data"


async def test_rotate_all(integration_client):
    """POST /v1/vault/rotate-all — verify response contains rotated count."""
    headers = await get_auth_headers(integration_client, "rotatealluser")

    # Create a couple of blobs
    for text in ["blob-one", "blob-two"]:
        resp = await integration_client.post(
            "/v1/vault/encrypt",
            json={"plaintext": text, "label": text},
            headers=headers,
        )
        assert resp.status_code == 200

    # Rotate all
    resp = await integration_client.post("/v1/vault/rotate-all", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "rotated" in data
    assert data["rotated"] >= 2
