"""Tests for zuultimate.ai_security.permissions -- RBAC for executive agents."""

from __future__ import annotations

from zuultimate.ai_security.permissions import (
    EXECUTIVE_TOOL_PERMISSIONS,
    ExecutivePermissions,
    ToolCategory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perms() -> ExecutivePermissions:
    return ExecutivePermissions()


# ---------------------------------------------------------------------------
# Full registry checks
# ---------------------------------------------------------------------------

def test_all_16_executives_present():
    assert len(EXECUTIVE_TOOL_PERMISSIONS) == 16


def test_list_agents():
    agents = _perms().list_agents()
    assert len(agents) == 16
    assert "CTO" in agents
    assert "CoS" in agents


# ---------------------------------------------------------------------------
# Full-access roles
# ---------------------------------------------------------------------------

def test_cto_full_access():
    p = _perms()
    for cat in ToolCategory:
        assert p.check("CTO", "any_tool", cat.value) is True


def test_ceng_full_access():
    p = _perms()
    for cat in ToolCategory:
        assert p.check("CEngO", "any_tool", cat.value) is True


def test_csec_full_access():
    p = _perms()
    for cat in ToolCategory:
        assert p.check("CSecO", "any_tool", cat.value) is True


def test_cos_full_access():
    p = _perms()
    for cat in ToolCategory:
        assert p.check("CoS", "any_tool", cat.value) is True


# ---------------------------------------------------------------------------
# Restricted roles
# ---------------------------------------------------------------------------

def test_cfo_restricted():
    p = _perms()
    # CFO has business/data/analysis/documents/general
    assert p.check("CFO", "t", "business") is True
    assert p.check("CFO", "t", "data") is True
    assert p.check("CFO", "t", "analysis") is True
    # CFO lacks devops, automation, security
    assert p.check("CFO", "t", "devops") is False
    assert p.check("CFO", "t", "automation") is False
    assert p.check("CFO", "t", "security") is False


def test_cmo_restricted():
    p = _perms()
    # CMO has communication/research/documents/general
    assert p.check("CMO", "t", "communication") is True
    assert p.check("CMO", "t", "research") is True
    # CMO lacks devops, data, automation
    assert p.check("CMO", "t", "devops") is False
    assert p.check("CMO", "t", "data") is False
    assert p.check("CMO", "t", "automation") is False


def test_cdo_categories():
    p = _perms()
    allowed = p.get_allowed_categories("CDO")
    for cat in ("data", "research", "analysis", "general"):
        assert cat in allowed


def test_cpo_categories():
    p = _perms()
    allowed = p.get_allowed_categories("CPO")
    for cat in ("research", "analysis", "documents", "business", "general"):
        assert cat in allowed


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_unknown_agent_denied():
    assert _perms().check("FAKE", "tool", "general") is False


def test_unknown_category_denied():
    assert _perms().check("CTO", "tool", "fake_category") is False


def test_get_allowed_categories():
    cats = _perms().get_allowed_categories("CFO")
    assert isinstance(cats, set)
    assert "business" in cats
    assert "devops" not in cats


# ---------------------------------------------------------------------------
# Security-aware roles
# ---------------------------------------------------------------------------

def test_crio_has_security():
    p = _perms()
    assert p.check("CRiO", "t", "security") is True


def test_ccomo_has_security():
    p = _perms()
    assert p.check("CComO", "t", "security") is True
