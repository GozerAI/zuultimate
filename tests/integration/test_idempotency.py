"""Integration tests for idempotency key support on POS transactions."""

import pytest

from tests.integration.conftest import get_auth_headers


async def _create_terminal(client, headers):
    resp = await client.post(
        "/v1/pos/terminals",
        json={"name": "Test POS", "location": "Store 1", "device_type": "register"},
        headers=headers,
    )
    return resp.json()["id"]


async def test_idempotent_transaction_returns_same_result(integration_client):
    headers = await get_auth_headers(integration_client)
    terminal_id = await _create_terminal(integration_client, headers)

    idem_key = "txn-unique-123"
    body = {"terminal_id": terminal_id, "amount": 42.50, "currency": "USD"}

    resp1 = await integration_client.post(
        "/v1/pos/transactions",
        json=body,
        headers={**headers, "X-Idempotency-Key": idem_key},
    )
    assert resp1.status_code == 200
    result1 = resp1.json()

    # Second request with same key should return cached response
    resp2 = await integration_client.post(
        "/v1/pos/transactions",
        json=body,
        headers={**headers, "X-Idempotency-Key": idem_key},
    )
    assert resp2.status_code == 200
    result2 = resp2.json()

    assert result1["id"] == result2["id"]
    assert result1["reference"] == result2["reference"]


async def test_different_idempotency_keys_create_separate_transactions(
    integration_client,
):
    headers = await get_auth_headers(integration_client)
    terminal_id = await _create_terminal(integration_client, headers)

    body = {"terminal_id": terminal_id, "amount": 10.00, "currency": "USD"}

    resp1 = await integration_client.post(
        "/v1/pos/transactions",
        json=body,
        headers={**headers, "X-Idempotency-Key": "key-a"},
    )
    resp2 = await integration_client.post(
        "/v1/pos/transactions",
        json=body,
        headers={**headers, "X-Idempotency-Key": "key-b"},
    )

    assert resp1.json()["id"] != resp2.json()["id"]


async def test_no_idempotency_key_creates_new_transaction_each_time(
    integration_client,
):
    headers = await get_auth_headers(integration_client)
    terminal_id = await _create_terminal(integration_client, headers)

    body = {"terminal_id": terminal_id, "amount": 5.00, "currency": "USD"}

    resp1 = await integration_client.post(
        "/v1/pos/transactions", json=body, headers=headers
    )
    resp2 = await integration_client.post(
        "/v1/pos/transactions", json=body, headers=headers
    )

    assert resp1.json()["id"] != resp2.json()["id"]
