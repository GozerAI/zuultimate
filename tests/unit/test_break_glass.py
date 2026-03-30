"""Tests for BreakGlassService — emergency access with dual approval."""

import pytest

from zuultimate.identity.workforce.break_glass import BreakGlassService


@pytest.fixture
async def bg_svc(test_db):
    return BreakGlassService(test_db)


@pytest.mark.asyncio
async def test_initiate_creates_pending_session(bg_svc):
    result = await bg_svc.initiate("user-1", "datacenter fire")
    assert result["status"] == "pending"
    assert result["user_id"] == "user-1"
    assert result["reason"] == "datacenter fire"
    assert result["audit_tag"].startswith("bg-")


@pytest.mark.asyncio
async def test_first_approval(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    result = await bg_svc.approve(session["id"], "approver-1")
    assert result["status"] == "partially_approved"
    assert result["first_approver_id"] == "approver-1"
    assert result["second_approver_id"] is None
    assert result["activated_at"] is None


@pytest.mark.asyncio
async def test_dual_approval_activates(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    await bg_svc.approve(session["id"], "approver-1")
    result = await bg_svc.approve(session["id"], "approver-2")
    assert result["status"] == "active"
    assert result["second_approver_id"] == "approver-2"
    assert result["activated_at"] is not None
    assert result["expires_at"] is not None


@pytest.mark.asyncio
async def test_self_approval_rejected(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    with pytest.raises(ValueError, match="cannot approve"):
        await bg_svc.approve(session["id"], "user-1")


@pytest.mark.asyncio
async def test_same_approver_twice_rejected(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    await bg_svc.approve(session["id"], "approver-1")
    with pytest.raises(ValueError, match="Same approver"):
        await bg_svc.approve(session["id"], "approver-1")


@pytest.mark.asyncio
async def test_approve_nonexistent_session(bg_svc):
    with pytest.raises(ValueError, match="not found"):
        await bg_svc.approve("bad-id", "approver-1")


@pytest.mark.asyncio
async def test_deactivate_session(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    await bg_svc.approve(session["id"], "approver-1")
    await bg_svc.approve(session["id"], "approver-2")
    result = await bg_svc.deactivate(session["id"])
    assert result["status"] == "deactivated"


@pytest.mark.asyncio
async def test_deactivate_nonexistent(bg_svc):
    with pytest.raises(ValueError, match="not found"):
        await bg_svc.deactivate("bad-id")


@pytest.mark.asyncio
async def test_session_ttl_is_2_hours(bg_svc):
    session = await bg_svc.initiate("user-1", "incident")
    await bg_svc.approve(session["id"], "approver-1")
    result = await bg_svc.approve(session["id"], "approver-2")
    delta = result["expires_at"] - result["activated_at"]
    assert delta.total_seconds() == 2 * 3600


@pytest.mark.asyncio
async def test_initiate_with_tenant(bg_svc):
    result = await bg_svc.initiate("user-1", "incident", tenant_id="tenant-1")
    assert result["tenant_id"] == "tenant-1"
