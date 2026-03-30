"""Unit tests for require_access dependency (access control enforcement)."""

import pytest

from zuultimate.access.service import AccessService
from zuultimate.identity.service import IdentityService


@pytest.fixture
async def setup(test_db, test_settings):
    """Set up identity and access services with a test user."""
    identity_svc = IdentityService(test_db, test_settings)
    access_svc = AccessService(test_db)
    user = await identity_svc.register("acl@test.com", "acluser", "password123")
    return {"identity": identity_svc, "access": access_svc, "user_id": user["id"]}


async def test_default_deny(setup):
    """Without any policies, access should be denied."""
    result = await setup["access"].check_access(
        user_id=setup["user_id"], resource="vault/encrypt", action="execute"
    )
    assert result["allowed"] is False


async def test_allow_policy_grants_access(setup):
    """An allow policy matching the resource and action should grant access."""
    svc = setup["access"]
    await svc.create_policy(
        name="allow-vault",
        effect="allow",
        resource_pattern="vault/*",
        action_pattern="*",
    )
    result = await svc.check_access(
        user_id=setup["user_id"], resource="vault/encrypt", action="execute"
    )
    assert result["allowed"] is True


async def test_deny_policy_overrides_allow(setup):
    """A deny policy with higher priority should override allow."""
    svc = setup["access"]
    await svc.create_policy(
        name="allow-all", effect="allow",
        resource_pattern="*", action_pattern="*", priority=0,
    )
    await svc.create_policy(
        name="deny-vault", effect="deny",
        resource_pattern="vault/*", action_pattern="*", priority=10,
    )
    result = await svc.check_access(
        user_id=setup["user_id"], resource="vault/encrypt", action="execute"
    )
    assert result["allowed"] is False

    # Other resources should still be allowed
    result = await svc.check_access(
        user_id=setup["user_id"], resource="pos/terminal", action="read"
    )
    assert result["allowed"] is True
