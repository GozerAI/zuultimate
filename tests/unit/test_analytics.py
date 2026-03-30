"""Tests for analytics modules (474, 482, 490, 497)."""
from zuultimate.analytics.behavior import BehaviorAnalyticsService
from zuultimate.analytics.feature_adoption import FeatureAdoptionService
from zuultimate.analytics.plg import PLGAnalyticsService
from zuultimate.analytics.engagement import EngagementScoringService

class TestBehaviorAnalytics:
    def setup_method(self):
        self.svc = BehaviorAnalyticsService()

    def test_track_event(self):
        e = self.svc.track("u1", "t1", "login")
        assert e.event_type == "login"

    def test_get_user_events(self):
        self.svc.track("u1", "t1", "login")
        self.svc.track("u1", "t1", "api_call")
        events = self.svc.get_user_events("u1")
        assert len(events) == 2

    def test_get_user_events_filtered(self):
        self.svc.track("u1", "t1", "login")
        self.svc.track("u1", "t1", "api_call")
        events = self.svc.get_user_events("u1", event_type="login")
        assert len(events) == 1

    def test_get_tenant_events(self):
        self.svc.track("u1", "t1", "login")
        self.svc.track("u2", "t1", "login")
        events = self.svc.get_tenant_events("t1")
        assert len(events) == 2

    def test_event_counts(self):
        self.svc.track("u1", "t1", "login")
        self.svc.track("u1", "t1", "login")
        self.svc.track("u1", "t1", "api_call")
        counts = self.svc.get_event_counts("t1")
        assert counts["login"] == 2
        assert counts["api_call"] == 1

    def test_active_users(self):
        self.svc.track("u1", "t1", "login")
        self.svc.track("u2", "t1", "login")
        users = self.svc.get_active_users("t1")
        assert len(users) == 2

    def test_user_journey(self):
        self.svc.track("u1", "t1", "signup")
        self.svc.track("u1", "t1", "onboarding")
        self.svc.track("u1", "t1", "first_api_call")
        journey = self.svc.get_user_journey("u1")
        assert len(journey) == 3

class TestFeatureAdoption:
    def setup_method(self):
        self.svc = FeatureAdoptionService()

    def test_record_and_get_adoption(self):
        self.svc.record_feature_use("t1", "u1", "sso")
        self.svc.record_feature_use("t1", "u2", "sso")
        result = self.svc.get_adoption_rate("t1", "sso", total_users=10)
        assert result["adopted_users"] == 2
        assert result["adoption_rate"] == 0.2

    def test_feature_ranking(self):
        self.svc.record_feature_use("t1", "u1", "sso")
        self.svc.record_feature_use("t1", "u1", "sso")
        self.svc.record_feature_use("t1", "u1", "mfa")
        ranking = self.svc.get_feature_ranking("t1")
        assert ranking[0]["feature"] == "sso"

    def test_user_feature_summary(self):
        self.svc.record_feature_use("t1", "u1", "sso")
        self.svc.record_feature_use("t1", "u1", "mfa")
        summary = self.svc.get_user_feature_summary("t1", "u1")
        assert "sso" in summary
        assert "mfa" in summary

class TestPLGAnalytics:
    def setup_method(self):
        self.svc = PLGAnalyticsService()

    def test_track_funnel(self):
        self.svc.track_funnel_step("u1", "signup_to_paid", "visit")
        self.svc.track_funnel_step("u1", "signup_to_paid", "signup")
        self.svc.track_funnel_step("u2", "signup_to_paid", "visit")
        analysis = self.svc.get_funnel_analysis("signup_to_paid")
        assert analysis["total_users"] == 2
        assert analysis["steps"]["visit"]["count"] == 2
        assert analysis["steps"]["signup"]["count"] == 1

    def test_track_conversion(self):
        self.svc.track_conversion("u1", "free", "pro", revenue=29)
        metrics = self.svc.get_conversion_metrics()
        assert metrics["total_conversions"] == 1
        assert metrics["total_revenue"] == 29

    def test_activation_rate(self):
        self.svc.track_funnel_step("u1", "onboarding", "signup")
        self.svc.track_funnel_step("u1", "onboarding", "first_api_call")
        self.svc.track_funnel_step("u2", "onboarding", "signup")
        rate = self.svc.get_activation_rate("onboarding", "first_api_call")
        assert rate == 0.5

class TestEngagementScoring:
    def setup_method(self):
        self.svc = EngagementScoringService()

    def test_compute_score(self):
        self.svc.record_event("u1", "t1", "login")
        self.svc.record_event("u1", "t1", "feature_use")
        self.svc.record_event("u1", "t1", "api_call")
        score = self.svc.compute_score("u1", "t1")
        assert score["score"] > 0
        assert score["level"] in ("power_user", "active", "casual", "at_risk")

    def test_inactive_user(self):
        score = self.svc.compute_score("u1", "t1")
        assert score["score"] == 0
        assert score["level"] == "inactive"

    def test_tenant_engagement(self):
        self.svc.record_event("u1", "t1", "login")
        self.svc.record_event("u2", "t1", "login")
        result = self.svc.get_tenant_engagement("t1", ["u1", "u2"])
        assert result["avg_score"] > 0

    def test_at_risk_users(self):
        self.svc.record_event("u1", "t1", "login")
        at_risk = self.svc.get_at_risk_users("t1", ["u1", "u2"])
        assert "u2" in at_risk
