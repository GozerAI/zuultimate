"""Tests for plan comparison (264) and recommendation (276)."""
from zuultimate.enterprise.plan_comparison import PlanComparisonService
from zuultimate.enterprise.plan_recommendation import PlanRecommendationEngine

class TestPlanComparison:
    def setup_method(self):
        self.svc = PlanComparisonService()

    def test_comparison_matrix(self):
        matrix = self.svc.get_comparison_matrix()
        assert len(matrix["plans"]) == 4
        plan_names = [p["plan"] for p in matrix["plans"]]
        assert "free" in plan_names
        assert "scale" in plan_names

    def test_plan_details(self):
        details = self.svc.get_plan_details("pro")
        assert details["plan"] == "pro"
        assert "features" in details

    def test_upgrade_path(self):
        path = self.svc.get_upgrade_path("free", "pro")
        assert path["upgrade_available"]
        assert len(path["new_features"]) > 0

    def test_no_downgrade_path(self):
        path = self.svc.get_upgrade_path("pro", "free")
        assert not path["upgrade_available"]

    def test_recommend_plan(self):
        result = self.svc.recommend_plan({"needs_sso": True})
        assert result == "growth"
        result = self.svc.recommend_plan({})
        assert result == "free"

class TestPlanRecommendation:
    def setup_method(self):
        self.engine = PlanRecommendationEngine()

    def test_low_usage_recommends_free(self):
        rec = self.engine.recommend({"api_calls_per_month": 10, "team_size": 1})
        assert rec["recommended_plan"] == "free"

    def test_high_usage_recommends_scale(self):
        rec = self.engine.recommend({"api_calls_per_month": 100000, "team_size": 100,
                                     "needs_sso": True, "storage_gb": 200})
        assert rec["recommended_plan"] == "scale"

    def test_compare_with_current(self):
        result = self.engine.compare_with_current("free",
            {"api_calls_per_month": 10000, "team_size": 15})
        assert result["should_upgrade"]
