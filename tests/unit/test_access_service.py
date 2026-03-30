"""Unit tests for AccessService."""

import pytest
from sqlalchemy import select

from zuultimate.access.models import AuditEntry, Role
from zuultimate.access.service import AccessService
from zuultimate.common.exceptions import NotFoundError, ValidationError


@pytest.fixture
def svc(test_db):
    return AccessService(test_db)


@pytest.fixture
async def role_id(test_db):
    """Create a test role and return its ID."""
    async with test_db.get_session("identity") as session:
        role = Role(name="admin", description="Admin role")
        session.add(role)
        await session.flush()
        return role.id


# ---------------------------------------------------------------------------
# create_policy
# ---------------------------------------------------------------------------


async def test_create_policy_allow(svc):
    result = await svc.create_policy(
        name="allow-all", effect="allow", resource_pattern="*", action_pattern="*"
    )
    assert result["name"] == "allow-all"
    assert result["effect"] == "allow"
    assert "id" in result


async def test_create_policy_deny(svc):
    result = await svc.create_policy(
        name="deny-vault", effect="deny", resource_pattern="vault/*", action_pattern="*"
    )
    assert result["effect"] == "deny"


async def test_create_policy_invalid_effect(svc):
    with pytest.raises(ValidationError, match="Effect must be"):
        await svc.create_policy(
            name="bad", effect="maybe", resource_pattern="*", action_pattern="*"
        )


async def test_create_policy_with_role(svc, role_id):
    result = await svc.create_policy(
        name="role-policy",
        effect="allow",
        resource_pattern="*",
        action_pattern="read",
        role_id=role_id,
    )
    assert result["role_id"] == role_id


# ---------------------------------------------------------------------------
# assign_role
# ---------------------------------------------------------------------------


async def test_assign_role_success(svc, role_id):
    result = await svc.assign_role(role_id, "user-1", assigned_by="admin")
    assert result["role_id"] == role_id
    assert result["user_id"] == "user-1"
    assert result["assigned_by"] == "admin"


async def test_assign_role_not_found(svc):
    with pytest.raises(NotFoundError, match="Role"):
        await svc.assign_role("nonexistent-role", "user-1")


async def test_assign_role_duplicate(svc, role_id):
    await svc.assign_role(role_id, "user-dup")
    with pytest.raises(ValidationError, match="already assigned"):
        await svc.assign_role(role_id, "user-dup")


# ---------------------------------------------------------------------------
# check_access
# ---------------------------------------------------------------------------


async def test_check_access_default_deny(svc):
    result = await svc.check_access("user-1", "vault/encrypt", "execute")
    assert result["allowed"] is False
    assert "default deny" in result["reason"]


async def test_check_access_global_allow(svc):
    await svc.create_policy(
        name="allow-all", effect="allow", resource_pattern="*", action_pattern="*"
    )
    result = await svc.check_access("user-1", "vault/encrypt", "execute")
    assert result["allowed"] is True


async def test_check_access_deny_overrides_allow(svc):
    await svc.create_policy(
        name="allow-all", effect="allow", resource_pattern="*", action_pattern="*", priority=0
    )
    await svc.create_policy(
        name="deny-vault", effect="deny", resource_pattern="vault/*", action_pattern="*", priority=10
    )
    result = await svc.check_access("user-1", "vault/encrypt", "execute")
    assert result["allowed"] is False
    assert "deny-vault" in result["reason"]


async def test_check_access_creates_audit(svc, test_db):
    await svc.check_access("audit-user", "some/resource", "read")
    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(AuditEntry).where(AuditEntry.user_id == "audit-user")
        )
        entry = result.scalar_one()
        assert entry.result == "deny"
        assert entry.resource == "some/resource"


async def test_check_access_role_scoped_policy(svc, role_id):
    await svc.assign_role(role_id, "scoped-user")
    await svc.create_policy(
        name="role-allow",
        effect="allow",
        resource_pattern="reports/*",
        action_pattern="read",
        role_id=role_id,
    )
    result = await svc.check_access("scoped-user", "reports/q1", "read")
    assert result["allowed"] is True

    # Different user without role should be denied
    result = await svc.check_access("other-user", "reports/q1", "read")
    assert result["allowed"] is False
