"""Tests for WorkforceAccessPolicy — ABAC policy engine."""

import pytest

from zuultimate.identity.workforce.policy import (
    Decision,
    PolicyResult,
    WorkforceAccessPolicy,
    WorkforceContext,
)


@pytest.fixture
def policy():
    return WorkforceAccessPolicy()


def _base_ctx(**overrides) -> WorkforceContext:
    """Create a valid baseline context that passes all mandatory checks."""
    defaults = {
        "user_id": "u1",
        "tenant_id": "t1",
        "device_id": "d1",
        "cert_valid": True,
        "mdm_enrolled": True,
        "disk_encrypted": True,
        "posture_score": 0.2,
        "resource": "data",
        "action": "read",
    }
    defaults.update(overrides)
    return WorkforceContext(**defaults)


# -- Mandatory checks --

def test_deny_invalid_cert(policy):
    ctx = _base_ctx(cert_valid=False)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.DENY
    assert "certificate" in result.reason.lower()


def test_deny_no_mdm(policy):
    ctx = _base_ctx(mdm_enrolled=False)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.DENY
    assert "MDM" in result.reason


def test_deny_no_disk_encryption(policy):
    ctx = _base_ctx(disk_encrypted=False)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.DENY
    assert "encryption" in result.reason.lower()


# -- Risk-adaptive --

def test_deny_high_posture_score(policy):
    ctx = _base_ctx(posture_score=0.9)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.DENY


def test_step_up_medium_posture_score(policy):
    ctx = _base_ctx(posture_score=0.7)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.STEP_UP


def test_allow_low_posture_score(policy):
    ctx = _base_ctx(posture_score=0.1)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.ALLOW


# -- Sovereignty --

def test_deny_us_only_non_us_no_jit(policy):
    ctx = _base_ctx(resource="us_only:secrets", sovereignty_ring="eu")
    result = policy.evaluate(ctx)
    assert result.decision == Decision.DENY
    assert "JIT" in result.reason


def test_allow_us_only_non_us_with_jit(policy):
    ctx = _base_ctx(
        resource="us_only:secrets",
        sovereignty_ring="eu",
        has_jit_grant=True,
        jit_scope="us_secrets",
    )
    result = policy.evaluate(ctx)
    assert result.decision == Decision.ALLOW


def test_allow_us_only_us_ring(policy):
    ctx = _base_ctx(resource="us_only:secrets", sovereignty_ring="us")
    result = policy.evaluate(ctx)
    assert result.decision == Decision.ALLOW


# -- Sensitivity --

def test_step_up_high_sensitivity_old_session(policy):
    ctx = _base_ctx(sensitivity="high", session_age_minutes=45)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.STEP_UP


def test_step_up_high_sensitivity_off_hours(policy):
    ctx = _base_ctx(sensitivity="high", is_off_hours=True)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.STEP_UP


def test_allow_high_sensitivity_fresh_session(policy):
    ctx = _base_ctx(sensitivity="high", session_age_minutes=10)
    result = policy.evaluate(ctx)
    assert result.decision == Decision.ALLOW


# -- TTL --

def test_ttl_high_sensitivity(policy):
    ctx = _base_ctx(sensitivity="high", session_age_minutes=5)
    result = policy.evaluate(ctx)
    assert result.ttl_seconds == 900  # 15 min


def test_ttl_medium_posture(policy):
    ctx = _base_ctx(posture_score=0.5)
    result = policy.evaluate(ctx)
    assert result.ttl_seconds == 1800  # 30 min


def test_ttl_normal(policy):
    ctx = _base_ctx(posture_score=0.1)
    result = policy.evaluate(ctx)
    assert result.ttl_seconds == 3600  # 1 hour


# -- Scopes --

def test_scopes_low_posture(policy):
    ctx = _base_ctx(posture_score=0.1)
    result = policy.evaluate(ctx)
    assert "workforce:read" in result.required_scopes
    assert "workforce:write" in result.required_scopes


def test_scopes_jit_grant_added(policy):
    ctx = _base_ctx(has_jit_grant=True, jit_scope="admin:write")
    result = policy.evaluate(ctx)
    assert "admin:write" in result.required_scopes
