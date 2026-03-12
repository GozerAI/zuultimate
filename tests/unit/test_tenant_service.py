"""Unit tests for tenant service."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.tenant_service import TenantService


@pytest.fixture
async def tenant_svc(test_db):
    return TenantService(test_db)


async def test_create_tenant(tenant_svc):
    result = await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    assert result["name"] == "Acme Corp"
    assert result["slug"] == "acme"
    assert result["is_active"] is True
    assert result["id"]


async def test_create_duplicate_slug_fails(tenant_svc):
    await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    with pytest.raises(ValidationError, match="already exists"):
        await tenant_svc.create_tenant(name="Other Corp", slug="acme")


async def test_list_tenants(tenant_svc):
    await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    await tenant_svc.create_tenant(name="Beta Inc", slug="beta")
    tenants = await tenant_svc.list_tenants()
    assert len(tenants) == 2
    names = {t["name"] for t in tenants}
    assert names == {"Acme Corp", "Beta Inc"}


async def test_list_tenants_active_only(tenant_svc):
    t = await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    await tenant_svc.create_tenant(name="Beta Inc", slug="beta")
    await tenant_svc.deactivate_tenant(t["id"])

    active = await tenant_svc.list_tenants(active_only=True)
    assert len(active) == 1
    assert active[0]["slug"] == "beta"


async def test_get_tenant(tenant_svc):
    created = await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    fetched = await tenant_svc.get_tenant(created["id"])
    assert fetched["slug"] == "acme"


async def test_get_nonexistent_tenant(tenant_svc):
    with pytest.raises(NotFoundError):
        await tenant_svc.get_tenant("nonexistent-id")


async def test_deactivate_tenant(tenant_svc):
    created = await tenant_svc.create_tenant(name="Acme Corp", slug="acme")
    result = await tenant_svc.deactivate_tenant(created["id"])
    assert result["is_active"] is False


async def test_deactivate_nonexistent_tenant(tenant_svc):
    with pytest.raises(NotFoundError):
        await tenant_svc.deactivate_tenant("nonexistent-id")
