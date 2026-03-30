"""Tests for enterprise feature gating (252, 255, 294, 308)."""
import pytest
from zuultimate.enterprise.feature_gate import (
    FeatureGateService, FeatureGateError, PlanTier, get_plan_tier,
    FEATURE_FLAGS, feature_gate_service,
)

class TestPlanTier:
    def test_free_tier(self):
        assert get_plan_tier("free") == PlanTier.FREE
        assert get_plan_tier("starter") == PlanTier.FREE

    def test_pro_tier(self):
        assert get_plan_tier("pro") == PlanTier.PRO

    def test_growth_tier(self):
        assert get_plan_tier("growth") == PlanTier.GROWTH
        assert get_plan_tier("business") == PlanTier.GROWTH

    def test_scale_tier(self):
        assert get_plan_tier("scale") == PlanTier.SCALE
        assert get_plan_tier("enterprise") == PlanTier.SCALE

    def test_unknown_defaults_free(self):
        assert get_plan_tier("unknown") == PlanTier.FREE

class TestFeatureGateService:
    def setup_method(self):
        self.svc = FeatureGateService()

    def test_free_gets_basic_features(self):
        assert self.svc.check_feature("free", "basic_auth")
        assert self.svc.check_feature("free", "basic_vault")
        assert self.svc.check_feature("free", "basic_mfa")

    def test_free_blocked_from_pro(self):
        assert not self.svc.check_feature("free", "sso_oidc")
        assert not self.svc.check_feature("free", "rbac_matrix")

    def test_pro_gets_pro_features(self):
        assert self.svc.check_feature("pro", "sso_oidc")
        assert self.svc.check_feature("pro", "rbac_matrix")
        assert self.svc.check_feature("pro", "basic_auth")

    def test_pro_blocked_from_growth(self):
        assert not self.svc.check_feature("pro", "sso_saml")
        assert not self.svc.check_feature("pro", "scim_provisioning")

    def test_scale_gets_all(self):
        for key in FEATURE_FLAGS:
            assert self.svc.check_feature("scale", key), key

    def test_require_feature_raises(self):
        with pytest.raises(FeatureGateError) as exc_info:
            self.svc.require_feature("free", "sso_oidc")
        assert exc_info.value.feature_key == "sso_oidc"

    def test_require_feature_passes(self):
        self.svc.require_feature("pro", "sso_oidc")

    def test_require_tier(self):
        with pytest.raises(FeatureGateError):
            self.svc.require_tier("free", PlanTier.PRO)
        self.svc.require_tier("pro", PlanTier.PRO)

    def test_unknown_feature_returns_false(self):
        assert not self.svc.check_feature("scale", "nonexistent_feature")

    def test_entitlement_check(self):
        assert self.svc.check_entitlement("pro", "trendscope:full")
        assert not self.svc.check_entitlement("free", "nexus:basic")

    def test_override_grants_access(self):
        self.svc.set_override("t1", "sso_saml", True)
        assert self.svc.check_feature("free", "sso_saml", tenant_id="t1")

    def test_override_blocks_access(self):
        self.svc.set_override("t1", "basic_auth", False)
        assert not self.svc.check_feature("scale", "basic_auth", tenant_id="t1")

    def test_remove_override(self):
        self.svc.set_override("t1", "sso_saml", True)
        assert self.svc.remove_override("t1", "sso_saml")
        assert not self.svc.check_feature("free", "sso_saml", tenant_id="t1")

    def test_preview_grants_temporary_access(self):
        self.svc.grant_preview("t1", "sso_saml", duration_seconds=3600)
        assert self.svc.check_feature("free", "sso_saml", tenant_id="t1")

    def test_revoke_preview(self):
        self.svc.grant_preview("t1", "sso_saml", duration_seconds=3600)
        self.svc.revoke_preview("t1", "sso_saml")
        assert not self.svc.check_feature("free", "sso_saml", tenant_id="t1")

    def test_get_locked_features(self):
        locked = self.svc.get_locked_features("free")
        keys = [f["key"] for f in locked]
        assert "sso_oidc" in keys
        assert "basic_auth" not in keys

    def test_get_available_features(self):
        features = self.svc.get_available_features("pro")
        available = [f for f in features if f["available"]]
        locked = [f for f in features if not f["available"]]
        assert len(available) > 0
        assert len(locked) > 0

    def test_security_upsell_free(self):
        upsell = self.svc.get_security_upsell("free")
        assert len(upsell) > 0
        assert any(u["feature"] == "sso_oidc" for u in upsell)

    def test_security_upsell_scale_empty(self):
        upsell = self.svc.get_security_upsell("scale")
        assert len(upsell) == 0

    def test_get_overrides(self):
        self.svc.set_override("t1", "sso_saml", True)
        overrides = self.svc.get_overrides("t1")
        assert overrides == {"sso_saml": True}

    def test_get_previews(self):
        exp = self.svc.grant_preview("t1", "sso_saml", duration_seconds=3600)
        previews = self.svc.get_previews("t1")
        assert "sso_saml" in previews

    def test_module_singleton(self):
        assert feature_gate_service is not None
