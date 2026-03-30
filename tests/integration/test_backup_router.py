"""Integration tests for backup & resilience router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_snapshot_and_restore_flow(integration_client):
    headers = await get_auth_headers(integration_client, "backupuser")
    resp = await integration_client.post(
        "/v1/backup/snapshots",
        json={"name": "daily-backup", "source": "/data/main"},
        headers=headers,
    )
    assert resp.status_code == 200
    snap = resp.json()
    assert snap["name"] == "daily-backup"
    assert snap["status"] == "completed"
    assert len(snap["checksum"]) == 64

    # Restore from snapshot
    resp = await integration_client.post(
        "/v1/backup/restore",
        json={"snapshot_id": snap["id"], "target": "/restore/path"},
        headers=headers,
    )
    assert resp.status_code == 200
    job = resp.json()
    assert job["status"] == "completed"
    assert job["snapshot_id"] == snap["id"]


async def test_restore_nonexistent_snapshot(integration_client):
    headers = await get_auth_headers(integration_client, "backupuser2")
    resp = await integration_client.post(
        "/v1/backup/restore",
        json={"snapshot_id": "nonexistent", "target": "/target"},
        headers=headers,
    )
    assert resp.status_code == 404


async def test_integrity_check(integration_client):
    headers = await get_auth_headers(integration_client, "backupuser3")
    resp = await integration_client.post(
        "/v1/backup/integrity-check",
        json={"target": "/data/main"},
        headers=headers,
    )
    assert resp.status_code == 200
    check = resp.json()
    assert check["passed"] is True
    assert check["status"] == "completed"


async def test_snapshot_validation(integration_client):
    headers = await get_auth_headers(integration_client, "backupuser4")
    resp = await integration_client.post(
        "/v1/backup/snapshots", json={"name": "", "source": "/data"},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_integrity_check_validation(integration_client):
    headers = await get_auth_headers(integration_client, "backupuser5")
    resp = await integration_client.post(
        "/v1/backup/integrity-check", json={"target": ""},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_backup_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/backup/snapshots", json={"name": "test", "source": "/data"},
    )
    assert resp.status_code in (401, 403)
