"""Tests for JITService — just-in-time access grants."""

import pytest

from zuultimate.identity.workforce.jit import JITService


@pytest.fixture
async def jit_svc(test_db):
    return JITService(test_db)


@pytest.mark.asyncio
async def test_request_grant(jit_svc):
    result = await jit_svc.request_grant("user-1", "admin:write", "emergency fix")
    assert result["status"] == "pending"
    assert result["user_id"] == "user-1"
    assert result["scope"] == "admin:write"
    assert result["reason"] == "emergency fix"
    assert result["id"]


@pytest.mark.asyncio
async def test_approve_grant(jit_svc):
    req = await jit_svc.request_grant("user-1", "admin:write", "need access")
    result = await jit_svc.approve_grant(req["id"], "approver-1")
    assert result["status"] == "active"
    assert result["approved_by"] == "approver-1"
    assert result["expires_at"] is not None


@pytest.mark.asyncio
async def test_cannot_self_approve(jit_svc):
    req = await jit_svc.request_grant("user-1", "scope", "reason")
    with pytest.raises(ValueError, match="self-approve"):
        await jit_svc.approve_grant(req["id"], "user-1")


@pytest.mark.asyncio
async def test_approve_nonexistent_grant(jit_svc):
    with pytest.raises(ValueError, match="not found"):
        await jit_svc.approve_grant("bad-id", "approver")


@pytest.mark.asyncio
async def test_double_approve_rejected(jit_svc):
    req = await jit_svc.request_grant("user-1", "scope", "reason")
    await jit_svc.approve_grant(req["id"], "approver-1")
    with pytest.raises(ValueError, match="not pending"):
        await jit_svc.approve_grant(req["id"], "approver-2")


@pytest.mark.asyncio
async def test_revoke_grant(jit_svc):
    req = await jit_svc.request_grant("user-1", "scope", "reason")
    await jit_svc.approve_grant(req["id"], "approver-1")
    result = await jit_svc.revoke_grant(req["id"])
    assert result["status"] == "revoked"


@pytest.mark.asyncio
async def test_revoke_nonexistent(jit_svc):
    with pytest.raises(ValueError, match="not found"):
        await jit_svc.revoke_grant("bad-id")


@pytest.mark.asyncio
async def test_check_active_grant_found(jit_svc):
    req = await jit_svc.request_grant("user-1", "admin:read", "need it")
    await jit_svc.approve_grant(req["id"], "approver-1")
    result = await jit_svc.check_active_grant("user-1", "admin:read")
    assert result is not None
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_check_active_grant_not_found(jit_svc):
    result = await jit_svc.check_active_grant("user-99", "scope")
    assert result is None


@pytest.mark.asyncio
async def test_check_active_grant_wrong_scope(jit_svc):
    req = await jit_svc.request_grant("user-1", "admin:read", "need it")
    await jit_svc.approve_grant(req["id"], "approver-1")
    result = await jit_svc.check_active_grant("user-1", "admin:write")
    assert result is None


@pytest.mark.asyncio
async def test_request_grant_with_tenant(jit_svc):
    result = await jit_svc.request_grant(
        "user-1", "scope", "reason", tenant_id="tenant-1"
    )
    assert result["tenant_id"] == "tenant-1"


@pytest.mark.asyncio
async def test_grant_ttl_is_4_hours(jit_svc):
    req = await jit_svc.request_grant("user-1", "scope", "reason")
    result = await jit_svc.approve_grant(req["id"], "approver-1")
    delta = result["expires_at"] - result["approved_at"]
    assert delta.total_seconds() == 4 * 3600
