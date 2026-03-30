"""Tests for WorkforceFederationService — SAML/OIDC federation."""

import pytest
from unittest.mock import MagicMock

from zuultimate.identity.workforce.federation import WorkforceFederationService


@pytest.fixture
def federation_svc():
    db = MagicMock()
    settings = MagicMock()
    return WorkforceFederationService(db, settings)


@pytest.mark.asyncio
async def test_initiate_saml_returns_redirect_url(federation_svc):
    result = await federation_svc.initiate_saml("entra-1", "https://app.com/callback")
    assert "redirect_url" in result
    assert "login.microsoftonline.com" in result["redirect_url"]
    assert result["provider_id"] == "entra-1"


@pytest.mark.asyncio
async def test_initiate_saml_returns_state(federation_svc):
    result = await federation_svc.initiate_saml("entra-1", "")
    assert "state" in result
    assert len(result["state"]) == 32  # 16 bytes hex


@pytest.mark.asyncio
async def test_initiate_saml_unique_state(federation_svc):
    r1 = await federation_svc.initiate_saml("p1", "")
    r2 = await federation_svc.initiate_saml("p1", "")
    assert r1["state"] != r2["state"]


@pytest.mark.asyncio
async def test_saml_callback_returns_user_dict(federation_svc):
    result = await federation_svc.handle_saml_callback("entra-1", "response", "state")
    assert "user_id" in result
    assert "email" in result
    assert "groups" in result
    assert "department" in result


@pytest.mark.asyncio
async def test_map_entra_claims_with_upn(federation_svc):
    claims = {
        "upn": "jane.doe@contoso.com",
        "name": "Jane Doe",
        "groups": ["group-1", "group-2"],
        "department": "Engineering",
    }
    mapped = await federation_svc.map_entra_claims(claims)
    assert mapped["email"] == "jane.doe@contoso.com"
    assert mapped["username"] == "jane.doe"
    assert mapped["display_name"] == "Jane Doe"
    assert mapped["groups"] == ["group-1", "group-2"]
    assert mapped["department"] == "Engineering"


@pytest.mark.asyncio
async def test_map_entra_claims_with_preferred_username(federation_svc):
    claims = {
        "upn": "alice@contoso.com",
        "preferred_username": "alice.smith@contoso.com",
    }
    mapped = await federation_svc.map_entra_claims(claims)
    assert mapped["username"] == "alice.smith"


@pytest.mark.asyncio
async def test_map_entra_claims_empty(federation_svc):
    mapped = await federation_svc.map_entra_claims({})
    assert mapped["email"] == ""
    assert mapped["username"] == ""
    assert mapped["display_name"] == ""
    assert mapped["groups"] == []
    assert mapped["department"] == ""


@pytest.mark.asyncio
async def test_map_entra_claims_email_fallback(federation_svc):
    claims = {"email": "bob@example.com"}
    mapped = await federation_svc.map_entra_claims(claims)
    assert mapped["email"] == "bob@example.com"


@pytest.mark.asyncio
async def test_federation_with_key_manager():
    db = MagicMock()
    settings = MagicMock()
    km = MagicMock()
    svc = WorkforceFederationService(db, settings, key_manager=km)
    assert svc.key_manager is km


@pytest.mark.asyncio
async def test_initiate_saml_includes_provider_in_url(federation_svc):
    result = await federation_svc.initiate_saml("my-provider", "")
    assert "provider=my-provider" in result["redirect_url"]


@pytest.mark.asyncio
async def test_map_entra_claims_groups_preserved(federation_svc):
    claims = {"groups": ["admin", "dev", "ops"]}
    mapped = await federation_svc.map_entra_claims(claims)
    assert len(mapped["groups"]) == 3


@pytest.mark.asyncio
async def test_callback_returns_empty_groups(federation_svc):
    result = await federation_svc.handle_saml_callback("p", "r", "s")
    assert result["groups"] == []
