"""Phase 2 Identity — capability-based authorization tests.

Tests cover:
- IdentityToken CRUD (resolve, get, deactivate)
- CapabilityToken lifecycle (grant, revoke, cascade, expiry)
- Delegation (attenuation, TTL clamping, non-delegatable rejection)
- DataShape CRUD and sensitivity classification
- PolicyDecision enforcement (allow, deny, allow_filtered)
- InteractionEnforcer integration scenarios
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.identity.phase2_models import (
    CapabilityToken,
    DataShape,
    IdentityToken,
    PolicyDecision,
)
from zuultimate.identity.phase2_service import InteractionEnforcer


@pytest.fixture
async def enforcer(test_db, test_settings):
    return InteractionEnforcer(test_db, test_settings)


@pytest.fixture
async def user_identity(enforcer):
    """Create a default user identity for tests."""
    return await enforcer.resolve_identity(
        entity_type="user",
        entity_id="user-001",
        tenant_id="tenant-001",
        display_name="Test User",
    )


@pytest.fixture
async def agent_identity(enforcer):
    """Create an agent identity for tests."""
    return await enforcer.resolve_identity(
        entity_type="agent",
        entity_id="cmo-echo",
        tenant_id="tenant-001",
        display_name="CMO Echo",
        metadata={"role": "marketing", "codename": "Echo"},
    )


@pytest.fixture
async def service_identity(enforcer):
    """Create a service identity for tests."""
    return await enforcer.resolve_identity(
        entity_type="service",
        entity_id="trendscope",
        display_name="TrendScope Service",
    )


# ── IdentityToken Tests ─────────────────────────────────────────────────────


class TestIdentityToken:
    async def test_resolve_creates_new_token(self, enforcer):
        token = await enforcer.resolve_identity(
            entity_type="user", entity_id="new-user", display_name="New User",
        )
        assert token.id is not None
        assert token.entity_type == "user"
        assert token.entity_id == "new-user"
        assert token.is_active is True

    async def test_resolve_returns_existing_token(self, enforcer, user_identity):
        token2 = await enforcer.resolve_identity(
            entity_type="user", entity_id="user-001",
        )
        assert token2.id == user_identity.id

    async def test_resolve_agent_identity(self, enforcer, agent_identity):
        assert agent_identity.entity_type == "agent"
        assert agent_identity.entity_id == "cmo-echo"
        meta = json.loads(agent_identity.metadata_json)
        assert meta["codename"] == "Echo"

    async def test_resolve_service_identity(self, enforcer, service_identity):
        assert service_identity.entity_type == "service"
        assert service_identity.tenant_id is None

    async def test_get_identity_token(self, enforcer, user_identity):
        fetched = await enforcer.get_identity_token(user_identity.id)
        assert fetched.entity_id == "user-001"

    async def test_get_identity_token_not_found(self, enforcer):
        from zuultimate.common.exceptions import NotFoundError
        with pytest.raises(NotFoundError):
            await enforcer.get_identity_token("nonexistent-id")

    async def test_deactivate_identity(self, enforcer, user_identity):
        await enforcer.deactivate_identity(user_identity.id)
        # Re-resolving should create a new token (old one inactive)
        new_token = await enforcer.resolve_identity(
            entity_type="user", entity_id="user-001",
        )
        assert new_token.id != user_identity.id


# ── CapabilityToken Tests ────────────────────────────────────────────────────


class TestCapabilityToken:
    async def test_grant_capability(self, enforcer, user_identity, agent_identity):
        cap = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="content:create",
            resource_scope="tenant/*/blog/*",
            ttl_seconds=3600,
        )
        assert cap.id is not None
        assert cap.capability == "content:create"
        assert cap.resource_scope == "tenant/*/blog/*"
        assert cap.granted_by == user_identity.id
        assert cap.revoked_at is None

    async def test_grant_with_constraints(self, enforcer, user_identity, agent_identity):
        cap = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="api:call",
            constraints={"max_calls": 100, "ip_range": "10.0.0.0/8"},
            ttl_seconds=1800,
        )
        constraints = json.loads(cap.constraints_json)
        assert constraints["max_calls"] == 100

    async def test_grant_invalid_ttl(self, enforcer, user_identity, agent_identity):
        from zuultimate.common.exceptions import ValidationError
        with pytest.raises(ValidationError):
            await enforcer.grant_capability(
                grantor_id=user_identity.id,
                grantee_id=agent_identity.id,
                capability="test",
                ttl_seconds=10,  # too short
            )

    async def test_grant_nonexistent_grantor(self, enforcer, agent_identity):
        from zuultimate.common.exceptions import NotFoundError
        with pytest.raises(NotFoundError, match="Grantor"):
            await enforcer.grant_capability(
                grantor_id="fake-id",
                grantee_id=agent_identity.id,
                capability="test",
            )

    async def test_list_capabilities(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="cap1",
        )
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="cap2",
        )
        caps = await enforcer.list_capabilities(agent_identity.id)
        assert len(caps) == 2

    async def test_revoke_capability(self, enforcer, user_identity, agent_identity):
        cap = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="revoke-me",
        )
        count = await enforcer.revoke_capability(cap.id)
        assert count == 1
        caps = await enforcer.list_capabilities(agent_identity.id, active_only=True)
        assert all(c.capability != "revoke-me" for c in caps)

    async def test_revoke_cascades_to_children(self, enforcer, user_identity, agent_identity, service_identity):
        # Grant parent capability (delegatable)
        parent = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="data:read",
            delegatable=True,
        )
        # Delegate to service
        child = await enforcer.delegate(
            parent_capability_id=parent.id,
            grantee_id=service_identity.id,
        )
        # Revoke parent → should cascade to child
        count = await enforcer.revoke_capability(parent.id)
        assert count == 2  # parent + child

        service_caps = await enforcer.list_capabilities(service_identity.id, active_only=True)
        assert len(service_caps) == 0


# ── Delegation Tests ─────────────────────────────────────────────────────────


class TestDelegation:
    async def test_delegate_capability(self, enforcer, user_identity, agent_identity, service_identity):
        parent = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="vault:encrypt",
            resource_scope="tenant/001/*",
            delegatable=True,
            ttl_seconds=7200,
        )
        child = await enforcer.delegate(
            parent_capability_id=parent.id,
            grantee_id=service_identity.id,
            ttl_seconds=3600,
        )
        assert child.parent_capability_id == parent.id
        assert child.capability == "vault:encrypt"
        assert child.delegatable is False  # delegated caps are not re-delegatable

    async def test_delegate_non_delegatable_rejected(self, enforcer, user_identity, agent_identity, service_identity):
        from zuultimate.common.exceptions import ValidationError
        parent = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="secret",
            delegatable=False,
        )
        with pytest.raises(ValidationError, match="not delegatable"):
            await enforcer.delegate(
                parent_capability_id=parent.id,
                grantee_id=service_identity.id,
            )

    async def test_delegate_ttl_clamped_to_parent(self, enforcer, user_identity, agent_identity, service_identity):
        parent = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="read",
            delegatable=True,
            ttl_seconds=600,  # 10 minutes
        )
        child = await enforcer.delegate(
            parent_capability_id=parent.id,
            grantee_id=service_identity.id,
            ttl_seconds=86400,  # asks for 24h, gets clamped
        )
        # Child should expire no later than parent
        assert child.expires_at <= parent.expires_at

    async def test_delegate_revoked_parent_rejected(self, enforcer, user_identity, agent_identity, service_identity):
        from zuultimate.common.exceptions import ValidationError
        parent = await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="revoked-cap",
            delegatable=True,
        )
        await enforcer.revoke_capability(parent.id)
        with pytest.raises(ValidationError, match="revoked"):
            await enforcer.delegate(
                parent_capability_id=parent.id,
                grantee_id=service_identity.id,
            )


# ── DataShape Tests ──────────────────────────────────────────────────────────


class TestDataShape:
    async def test_create_data_shape(self, enforcer):
        shape = await enforcer.create_data_shape(
            name="trend_data",
            sensitivity="confidential",
            pii_fields=["analyst_email", "source_ip"],
            retention_days=90,
        )
        assert shape.id is not None
        assert shape.name == "trend_data"
        assert shape.sensitivity == "confidential"
        assert shape.retention_days == 90

    async def test_create_data_shape_invalid_sensitivity(self, enforcer):
        from zuultimate.common.exceptions import ValidationError
        with pytest.raises(ValidationError, match="Sensitivity"):
            await enforcer.create_data_shape(name="bad", sensitivity="top-secret")

    async def test_get_data_shape(self, enforcer):
        await enforcer.create_data_shape(name="user_profile", sensitivity="internal")
        shape = await enforcer.get_data_shape("user_profile")
        assert shape is not None
        assert shape.name == "user_profile"

    async def test_get_data_shape_not_found(self, enforcer):
        shape = await enforcer.get_data_shape("nonexistent")
        assert shape is None

    async def test_list_data_shapes(self, enforcer):
        await enforcer.create_data_shape(name="shape1")
        await enforcer.create_data_shape(name="shape2")
        shapes = await enforcer.list_data_shapes()
        assert len(shapes) >= 2


# ── Enforcement Tests ────────────────────────────────────────────────────────


class TestEnforcement:
    async def test_enforce_allow(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="content:create",
            resource_scope="*",
        )
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="tenant/001/blog/post-1",
            action="content:create",
        )
        assert decision.decision == "allow"

    async def test_enforce_deny_no_capability(self, enforcer, agent_identity):
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="tenant/001/vault/secrets",
            action="vault:decrypt",
        )
        assert decision.decision == "deny"
        assert "No matching capability" in decision.reason

    async def test_enforce_deny_inactive_identity(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="anything",
        )
        await enforcer.deactivate_identity(agent_identity.id)
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="anything",
            action="anything",
        )
        assert decision.decision == "deny"
        assert "inactive" in decision.reason.lower()

    async def test_enforce_allow_filtered_with_data_shape(self, enforcer, user_identity, agent_identity):
        # Create a confidential data shape with PII fields
        await enforcer.create_data_shape(
            name="financial_report",
            sensitivity="confidential",
            pii_fields=["ssn", "bank_account"],
        )
        # Grant agent a capability
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="data:read",
            resource_scope="*",
        )
        # Agent (clearance=1) accessing confidential (level=2) data
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="reports/q1",
            action="data:read",
            data_shape_name="financial_report",
        )
        assert decision.decision == "allow_filtered"
        filtered = json.loads(decision.filtered_fields_json)
        assert "ssn" in filtered
        assert "bank_account" in filtered

    async def test_enforce_wildcard_capability(self, enforcer, user_identity, service_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=service_identity.id,
            capability="*",
            resource_scope="*",
        )
        decision = await enforcer.enforce(
            identity_token_id=service_identity.id,
            resource="anything/goes",
            action="any:action:here",
        )
        assert decision.decision == "allow"

    async def test_enforce_hierarchical_capability(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="vault:*",
            resource_scope="*",
        )
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="vault/keys",
            action="vault:encrypt",
        )
        assert decision.decision == "allow"

    async def test_enforce_records_latency(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="test",
            resource_scope="*",
        )
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="test",
            action="test",
        )
        assert decision.latency_ms >= 0

    async def test_enforce_resource_scope_mismatch(self, enforcer, user_identity, agent_identity):
        await enforcer.grant_capability(
            grantor_id=user_identity.id,
            grantee_id=agent_identity.id,
            capability="data:read",
            resource_scope="tenant/001/*",
        )
        decision = await enforcer.enforce(
            identity_token_id=agent_identity.id,
            resource="tenant/999/secrets",
            action="data:read",
        )
        assert decision.decision == "deny"
