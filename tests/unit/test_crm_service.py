"""Unit tests for CRMService."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.crm.service import CRMService


@pytest.fixture
def svc(test_db):
    return CRMService(test_db)


# ---------------------------------------------------------------------------
# create_config
# ---------------------------------------------------------------------------


async def test_create_config_success(svc):
    result = await svc.create_config("salesforce", api_url="https://sf.example.com")
    assert result["provider"] == "salesforce"
    assert result["api_url"] == "https://sf.example.com"
    assert result["is_active"] is True
    assert "id" in result


async def test_create_config_empty_provider_raises(svc):
    with pytest.raises(ValidationError, match="empty"):
        await svc.create_config("")


async def test_create_config_default_url(svc):
    result = await svc.create_config("hubspot")
    assert result["api_url"] == ""


# ---------------------------------------------------------------------------
# start_sync
# ---------------------------------------------------------------------------


async def test_start_sync_success(svc):
    config = await svc.create_config("salesforce")
    result = await svc.start_sync(config["id"])
    assert result["config_id"] == config["id"]
    assert result["status"] == "pending"
    assert result["records_synced"] == 0


async def test_start_sync_nonexistent_config(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.start_sync("nonexistent-config-id")


# ---------------------------------------------------------------------------
# get_sync_status
# ---------------------------------------------------------------------------


async def test_get_sync_status_success(svc):
    config = await svc.create_config("salesforce")
    job = await svc.start_sync(config["id"])
    result = await svc.get_sync_status(job["id"])
    assert result["id"] == job["id"]
    assert result["status"] == "pending"


async def test_get_sync_status_not_found(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.get_sync_status("nonexistent-job-id")
