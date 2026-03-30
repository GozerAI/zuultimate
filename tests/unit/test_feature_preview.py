"""Tests for feature preview/trial (279)."""
from zuultimate.enterprise.feature_preview import FeaturePreviewService

class TestFeaturePreview:
    def setup_method(self):
        self.svc = FeaturePreviewService()

    def test_start_preview(self):
        p = self.svc.start_preview("t1", "sso_saml")
        assert p.is_active
        assert p.feature_key == "sso_saml"

    def test_check_preview(self):
        self.svc.start_preview("t1", "sso_saml")
        assert self.svc.check_preview("t1", "sso_saml") is not None

    def test_no_preview_returns_none(self):
        assert self.svc.check_preview("t1", "sso_saml") is None

    def test_record_usage(self):
        p = self.svc.start_preview("t1", "sso_saml")
        self.svc.record_usage(p.preview_id)
        assert p.usage_count == 1

    def test_end_preview(self):
        p = self.svc.start_preview("t1", "sso_saml")
        self.svc.end_preview(p.preview_id)
        assert not p.is_active

    def test_get_active_previews(self):
        self.svc.start_preview("t1", "sso_saml")
        self.svc.start_preview("t1", "custom_rbac")
        previews = self.svc.get_active_previews("t1")
        assert len(previews) == 2

    def test_preview_summary(self):
        p = self.svc.start_preview("t1", "sso_saml")
        self.svc.record_usage(p.preview_id)
        summary = self.svc.get_preview_summary(p.preview_id)
        assert summary["usage_count"] == 1
        assert summary["remaining_hours"] > 0
