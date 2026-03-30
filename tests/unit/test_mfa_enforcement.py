"""Tests for MFA enforcement (409)."""
from zuultimate.enterprise.mfa_enforcement import MFAEnforcementService

class TestMFAEnforcement:
    def setup_method(self):
        self.svc = MFAEnforcementService()

    def test_set_policy(self):
        p = self.svc.set_policy("t1", required=True)
        assert p.required

    def test_check_compliance_no_policy(self):
        result = self.svc.check_compliance("t1", False)
        assert result["compliant"]

    def test_check_compliance_mfa_enabled(self):
        self.svc.set_policy("t1", required=True, enforce_for_roles=["admin"])
        result = self.svc.check_compliance("t1", True, "admin")
        assert result["compliant"]

    def test_check_compliance_mfa_missing(self):
        self.svc.set_policy("t1", required=True, enforce_for_roles=["admin"])
        result = self.svc.check_compliance("t1", False, "admin")
        assert not result["compliant"]

    def test_role_not_enforced(self):
        self.svc.set_policy("t1", required=True, enforce_for_roles=["admin"])
        result = self.svc.check_compliance("t1", False, "member")
        assert result["compliant"]

    def test_remove_policy(self):
        self.svc.set_policy("t1", required=True)
        assert self.svc.remove_policy("t1")
        assert self.svc.get_policy("t1") is None
