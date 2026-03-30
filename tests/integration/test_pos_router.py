"""Integration tests for POS router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_terminal_and_transaction_flow(integration_client):
    headers = await get_auth_headers(integration_client, "posuser")
    resp = await integration_client.post(
        "/v1/pos/terminals",
        json={"name": "POS-1", "location": "Main Store", "device_type": "register"},
        headers=headers,
    )
    assert resp.status_code == 200
    terminal = resp.json()
    assert terminal["name"] == "POS-1"

    resp = await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal["id"], "amount": 99.99},
        headers=headers,
    )
    assert resp.status_code == 200
    txn = resp.json()
    assert txn["status"] == "completed"
    assert txn["reference"].startswith("TXN-")


async def test_transaction_nonexistent_terminal(integration_client):
    headers = await get_auth_headers(integration_client, "posuser2")
    resp = await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": "nonexistent", "amount": 10.0},
        headers=headers,
    )
    assert resp.status_code == 404


async def test_fraud_alert_high_amount(integration_client):
    headers = await get_auth_headers(integration_client, "posuser3")
    resp = await integration_client.post(
        "/v1/pos/terminals", json={"name": "T-fraud"}, headers=headers,
    )
    terminal_id = resp.json()["id"]

    await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 15000.0},
        headers=headers,
    )

    resp = await integration_client.get("/v1/pos/fraud-alerts", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) >= 1
    types = {item["alert_type"] for item in data["items"]}
    assert "high_amount" in types
    assert data["pagination"]["total"] >= 1


async def test_fraud_alerts_empty(integration_client):
    headers = await get_auth_headers(integration_client, "posuser4")
    resp = await integration_client.get("/v1/pos/fraud-alerts", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["pagination"]["total"] == 0


async def test_fraud_alerts_filter_resolved(integration_client):
    headers = await get_auth_headers(integration_client, "posuser5")
    resp = await integration_client.post(
        "/v1/pos/terminals", json={"name": "T-filter"}, headers=headers,
    )
    terminal_id = resp.json()["id"]

    await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 20000.0},
        headers=headers,
    )

    resp = await integration_client.get("/v1/pos/fraud-alerts?resolved=false", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()["items"]) >= 1

    resp = await integration_client.get("/v1/pos/fraud-alerts?resolved=true", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 0


async def test_pos_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/pos/terminals", json={"name": "T1"},
    )
    assert resp.status_code in (401, 403)


async def test_create_settlement(integration_client):
    headers = await get_auth_headers(integration_client, "posuser_stl1")
    # Register a terminal
    resp = await integration_client.post(
        "/v1/pos/terminals",
        json={"name": "STL-Terminal", "location": "Store A", "device_type": "register"},
        headers=headers,
    )
    assert resp.status_code == 200
    terminal_id = resp.json()["id"]

    # Create a transaction so settlement has something to batch
    resp = await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 50.00},
        headers=headers,
    )
    assert resp.status_code == 200

    # Create settlement
    resp = await integration_client.post(
        f"/v1/pos/settlements/{terminal_id}", headers=headers,
    )
    assert resp.status_code == 200
    settlement = resp.json()
    assert settlement["terminal_id"] == terminal_id
    assert settlement["transaction_count"] == 1
    assert settlement["total_amount"] == 50.00
    assert settlement["status"] == "settled"
    assert settlement["reference"].startswith("STL-")


async def test_get_settlement(integration_client):
    headers = await get_auth_headers(integration_client, "posuser_stl2")
    # Register terminal + create transaction + settle
    resp = await integration_client.post(
        "/v1/pos/terminals", json={"name": "STL-Get"}, headers=headers,
    )
    terminal_id = resp.json()["id"]
    await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 75.50},
        headers=headers,
    )
    resp = await integration_client.post(
        f"/v1/pos/settlements/{terminal_id}", headers=headers,
    )
    settlement_id = resp.json()["id"]

    # Get settlement by ID
    resp = await integration_client.get(
        f"/v1/pos/settlements/{settlement_id}", headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == settlement_id
    assert data["total_amount"] == 75.50
    assert data["transaction_count"] == 1
    assert data["status"] == "settled"


async def test_reconcile(integration_client):
    headers = await get_auth_headers(integration_client, "posuser_recon")
    # Register terminal
    resp = await integration_client.post(
        "/v1/pos/terminals", json={"name": "Recon-T"}, headers=headers,
    )
    terminal_id = resp.json()["id"]

    # Create two transactions
    await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 100.00},
        headers=headers,
    )
    await integration_client.post(
        "/v1/pos/transactions",
        json={"terminal_id": terminal_id, "amount": 200.00},
        headers=headers,
    )

    # Settle the transactions
    await integration_client.post(
        f"/v1/pos/settlements/{terminal_id}", headers=headers,
    )

    # Reconcile
    resp = await integration_client.get(
        f"/v1/pos/reconcile/{terminal_id}", headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["terminal_id"] == terminal_id
    assert data["batch_total"] == 300.00
    assert data["transaction_total"] == 300.00
    assert data["discrepancy"] == 0.0
    assert data["reconciled"] is True
