"""Unit tests for consumer password vault."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.vault.password_vault import PasswordVaultService


@pytest.fixture
def svc(test_db, test_settings):
    return PasswordVaultService(test_db, test_settings)


async def test_store_and_retrieve(svc):
    stored = await svc.store_secret("user1", "GitHub Token", "ghp_abc123")
    assert stored["name"] == "GitHub Token"
    assert "id" in stored

    retrieved = await svc.get_secret("user1", stored["id"])
    assert retrieved["value"] == "ghp_abc123"
    assert retrieved["name"] == "GitHub Token"


async def test_store_with_category(svc):
    stored = await svc.store_secret("user1", "API Key", "key-123", category="api_key")
    assert stored["category"] == "api_key"


async def test_list_secrets(svc):
    await svc.store_secret("user1", "Secret A", "val-a")
    await svc.store_secret("user1", "Secret B", "val-b")
    await svc.store_secret("user2", "Secret C", "val-c")

    user1_secrets = await svc.list_secrets("user1")
    assert len(user1_secrets) == 2
    # Values should not be in list response
    assert all("value" not in s for s in user1_secrets)


async def test_delete_secret(svc):
    stored = await svc.store_secret("user1", "Temp", "temp-val")
    result = await svc.delete_secret("user1", stored["id"])
    assert result["deleted"] is True

    with pytest.raises(NotFoundError):
        await svc.get_secret("user1", stored["id"])


async def test_delete_nonexistent(svc):
    with pytest.raises(NotFoundError):
        await svc.delete_secret("user1", "nonexistent")


async def test_get_wrong_user(svc):
    stored = await svc.store_secret("user1", "Private", "secret")
    with pytest.raises(NotFoundError):
        await svc.get_secret("user2", stored["id"])


async def test_update_existing_name(svc):
    await svc.store_secret("user1", "Reuse", "original")
    await svc.store_secret("user1", "Reuse", "updated")

    secrets = await svc.list_secrets("user1")
    assert len(secrets) == 1

    retrieved = await svc.get_secret("user1", secrets[0]["id"])
    assert retrieved["value"] == "updated"


async def test_empty_name_rejected(svc):
    with pytest.raises(ValidationError, match="name"):
        await svc.store_secret("user1", "", "value")


async def test_empty_value_rejected(svc):
    with pytest.raises(ValidationError, match="value"):
        await svc.store_secret("user1", "name", "")
