"""Unit tests for automated security policy enforcement (item 892)."""

import pytest

from zuultimate.compliance.policy_enforcer import (
    PolicyAction,
    PolicyEnforcer,
    PolicyResult,
    PolicySeverity,
    PolicyViolation,
    SecurityPolicy,
    create_default_enforcer,
)


class TestPolicyEnforcer:
    @pytest.fixture
    def enforcer(self):
        return PolicyEnforcer()

    def test_empty_enforcer_allows_all(self, enforcer):
        result = enforcer.evaluate({"anything": True})
        assert result.allowed
        assert not result.has_violations

    def test_add_and_match_deny_policy(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="test-deny", name="Test Deny", description="Deny if bad=True",
            severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
            condition=lambda ctx: ctx.get("bad", False),
        ))
        result = enforcer.evaluate({"bad": True})
        assert not result.allowed
        assert result.has_violations
        assert len(result.violations) == 1
        assert result.violations[0].policy_id == "test-deny"

    def test_allow_policy_does_not_deny(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="test-audit", name="Audit Only", description="Audit",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True,
        ))
        result = enforcer.evaluate({})
        assert result.allowed
        assert result.has_violations

    def test_remove_policy(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.LOW, action=PolicyAction.DENY,
            condition=lambda ctx: True,
        ))
        assert enforcer.remove_policy("p1")
        assert not enforcer.remove_policy("nonexistent")
        result = enforcer.evaluate({})
        assert result.allowed

    def test_disable_enable_policy(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
            condition=lambda ctx: True,
        ))
        enforcer.disable_policy("p1")
        result = enforcer.evaluate({})
        assert result.allowed

        enforcer.enable_policy("p1")
        result = enforcer.evaluate({})
        assert not result.allowed

    def test_evaluate_batch(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
            condition=lambda ctx: ctx.get("bad", False),
        ))
        results = enforcer.evaluate_batch([{"bad": True}, {"bad": False}, {"bad": True}])
        assert len(results) == 3
        assert not results[0].allowed
        assert results[1].allowed
        assert not results[2].allowed

    def test_get_policies_by_tag(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True, tags=["auth", "session"],
        ))
        enforcer.add_policy(SecurityPolicy(
            id="p2", name="P2", description="P2",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True, tags=["data"],
        ))
        assert len(enforcer.get_policies_by_tag("auth")) == 1
        assert len(enforcer.get_policies_by_tag("data")) == 1
        assert len(enforcer.get_policies_by_tag("missing")) == 0

    def test_highest_severity(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True,
        ))
        enforcer.add_policy(SecurityPolicy(
            id="p2", name="P2", description="P2",
            severity=PolicySeverity.CRITICAL, action=PolicyAction.DENY,
            condition=lambda ctx: True,
        ))
        result = enforcer.evaluate({})
        assert result.highest_severity == PolicySeverity.CRITICAL

    def test_no_violations_highest_severity_none(self, enforcer):
        result = enforcer.evaluate({})
        assert result.highest_severity is None

    def test_condition_exception_skipped(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.HIGH, action=PolicyAction.DENY,
            condition=lambda ctx: ctx["missing_key"],  # KeyError
        ))
        result = enforcer.evaluate({})
        assert result.allowed

    def test_policies_property(self, enforcer):
        assert len(enforcer.policies) == 0
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True,
        ))
        assert len(enforcer.policies) == 1

    def test_matched_policies(self, enforcer):
        enforcer.add_policy(SecurityPolicy(
            id="p1", name="P1", description="P1",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: True,
        ))
        enforcer.add_policy(SecurityPolicy(
            id="p2", name="P2", description="P2",
            severity=PolicySeverity.LOW, action=PolicyAction.AUDIT,
            condition=lambda ctx: False,
        ))
        result = enforcer.evaluate({})
        assert "p1" in result.matched_policies
        assert "p2" not in result.matched_policies


class TestDefaultEnforcer:
    @pytest.fixture
    def enforcer(self):
        return create_default_enforcer()

    def test_short_password_denied(self, enforcer):
        result = enforcer.evaluate({"password": "short"})
        assert not result.allowed

    def test_long_password_allowed(self, enforcer):
        result = enforcer.evaluate({"password": "a-very-long-secure-pass"})
        assert result.allowed

    def test_plaintext_secret_denied(self, enforcer):
        result = enforcer.evaluate({"payload": "data password=mysecret"})
        assert not result.allowed

    def test_admin_without_mfa(self, enforcer):
        result = enforcer.evaluate({"action_type": "admin", "mfa_verified": False})
        assert result.has_violations
        v = [v for v in result.violations if v.action == PolicyAction.REQUIRE_MFA]
        assert len(v) == 1

    def test_admin_with_mfa_ok(self, enforcer):
        result = enforcer.evaluate({"action_type": "admin", "mfa_verified": True})
        mfa_violations = [v for v in result.violations if v.action == PolicyAction.REQUIRE_MFA]
        assert len(mfa_violations) == 0

    def test_session_max_age(self, enforcer):
        result = enforcer.evaluate({"session_age_hours": 25})
        assert not result.allowed

    def test_geo_restriction(self, enforcer):
        result = enforcer.evaluate({"country_code": "XX", "blocked_countries": ["XX", "YY"]})
        assert not result.allowed
