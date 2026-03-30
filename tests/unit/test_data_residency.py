"""Unit tests for data residency controls (security module)."""

import pytest

from zuultimate.security.data_residency import (
    DataResidencyController,
    Region,
    ResidencyRequirement,
    ResidencyViolation,
    TenantResidencyConfig,
)


class TestTenantResidencyConfig:
    def test_defaults(self):
        cfg = TenantResidencyConfig(tenant_id="t1", home_region=Region.EU)
        assert cfg.allowed_regions == [Region.EU]
        assert cfg.pii_region == Region.EU

    def test_region_allowed_strict(self):
        cfg = TenantResidencyConfig(
            tenant_id="t1", home_region=Region.EU,
            requirement=ResidencyRequirement.STRICT,
            allowed_regions=[Region.EU, Region.UK],
        )
        assert cfg.is_region_allowed(Region.EU)
        assert cfg.is_region_allowed(Region.UK)
        assert not cfg.is_region_allowed(Region.US)
        assert not cfg.is_region_allowed(Region.GLOBAL)

    def test_region_allowed_none(self):
        cfg = TenantResidencyConfig(
            tenant_id="t1", home_region=Region.EU,
            requirement=ResidencyRequirement.NONE,
        )
        assert cfg.is_region_allowed(Region.US)
        assert cfg.is_region_allowed(Region.GLOBAL)

    def test_pii_region_check(self):
        cfg = TenantResidencyConfig(
            tenant_id="t1", home_region=Region.EU,
            pii_region=Region.EU,
        )
        assert cfg.is_pii_region_allowed(Region.EU)
        assert not cfg.is_pii_region_allowed(Region.US)


class TestDataResidencyController:
    @pytest.fixture
    def controller(self):
        c = DataResidencyController(current_region=Region.US)
        c.register_tenant(TenantResidencyConfig(
            tenant_id="eu-tenant", home_region=Region.EU,
            requirement=ResidencyRequirement.STRICT,
        ))
        c.register_tenant(TenantResidencyConfig(
            tenant_id="us-tenant", home_region=Region.US,
        ))
        c.register_tenant(TenantResidencyConfig(
            tenant_id="flex-tenant", home_region=Region.EU,
            requirement=ResidencyRequirement.NONE,
        ))
        return c

    def test_write_to_wrong_region_pii(self, controller):
        violation = controller.check_write("eu-tenant", "users")
        assert violation is not None
        assert violation.tenant_id == "eu-tenant"
        assert "PII" in violation.message

    def test_write_to_correct_region(self, controller):
        violation = controller.check_write("us-tenant", "users")
        assert violation is None

    def test_write_non_pii_wrong_region(self, controller):
        violation = controller.check_write("eu-tenant", "audit_logs")
        assert violation is not None

    def test_write_no_restriction(self, controller):
        # NONE requirement allows non-PII data anywhere
        violation = controller.check_write("flex-tenant", "audit_logs")
        assert violation is None

    def test_write_no_restriction_pii_still_enforced(self, controller):
        # PII region is always strict per is_pii_region_allowed
        violation = controller.check_write("flex-tenant", "users")
        assert violation is not None

    def test_write_unregistered_tenant(self, controller):
        violation = controller.check_write("unknown", "users")
        assert violation is None

    def test_read_pii_strict_wrong_region(self, controller):
        violation = controller.check_read("eu-tenant", "users")
        assert violation is not None

    def test_read_non_pii_ok(self, controller):
        violation = controller.check_read("eu-tenant", "audit_logs")
        assert violation is None

    def test_read_preferred_always_ok(self, controller):
        violation = controller.check_read("flex-tenant", "users")
        assert violation is None

    def test_unregister(self, controller):
        assert controller.unregister_tenant("eu-tenant")
        assert not controller.unregister_tenant("eu-tenant")
        assert controller.check_write("eu-tenant", "users") is None

    def test_get_config(self, controller):
        cfg = controller.get_config("eu-tenant")
        assert cfg is not None
        assert cfg.home_region == Region.EU

    def test_violations_summary(self, controller):
        s = controller.get_violations_summary()
        assert s["current_region"] == "us"
        assert s["registered_tenants"] == 3
        assert s["strict_tenants"] >= 1
        assert s["tenants_in_region"] >= 1

    def test_pii_data_types(self, controller):
        # All PII data types should trigger violations for EU tenant
        pii_types = ["users", "credentials", "user_sessions", "auth_events", "mfa_devices"]
        for dt in pii_types:
            violation = controller.check_write("eu-tenant", dt)
            assert violation is not None, f"Expected violation for {dt}"
