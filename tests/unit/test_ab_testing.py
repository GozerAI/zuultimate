"""Tests for A/B testing framework (258)."""
from zuultimate.enterprise.ab_testing import ABTestingService, ABVariant

class TestABTesting:
    def setup_method(self):
        self.svc = ABTestingService()

    def test_create_experiment(self):
        exp = self.svc.create_experiment("pricing_test")
        assert exp.experiment_id.startswith("exp-")
        assert exp.is_active
        assert len(exp.variants) == 2

    def test_get_variant_deterministic(self):
        exp = self.svc.create_experiment("test")
        v1 = self.svc.get_variant(exp.experiment_id, "user-1")
        v2 = self.svc.get_variant(exp.experiment_id, "user-1")
        assert v1.name == v2.name

    def test_record_conversion(self):
        exp = self.svc.create_experiment("test")
        self.svc.get_variant(exp.experiment_id, "user-1")
        conv = self.svc.record_conversion(exp.experiment_id, "user-1", "signup", value=29.0)
        assert conv is not None
        assert conv.value == 29.0

    def test_get_results(self):
        exp = self.svc.create_experiment("test")
        self.svc.get_variant(exp.experiment_id, "user-1")
        self.svc.get_variant(exp.experiment_id, "user-2")
        results = self.svc.get_results(exp.experiment_id)
        assert results["experiment_id"] == exp.experiment_id
        assert "control" in results["variants"] or "treatment" in results["variants"]

    def test_end_experiment(self):
        exp = self.svc.create_experiment("test")
        ended = self.svc.end_experiment(exp.experiment_id)
        assert not ended.is_active

    def test_list_experiments(self):
        self.svc.create_experiment("test1")
        self.svc.create_experiment("test2")
        assert len(self.svc.list_experiments()) == 2

    def test_custom_variants(self):
        variants = [ABVariant("a", 0.33), ABVariant("b", 0.33), ABVariant("c", 0.34)]
        exp = self.svc.create_experiment("multi", variants=variants)
        assert len(exp.variants) == 3

    def test_no_conversion_without_assignment(self):
        exp = self.svc.create_experiment("test")
        conv = self.svc.record_conversion(exp.experiment_id, "unknown-user", "signup")
        assert conv is None

    def test_inactive_experiment_returns_none(self):
        exp = self.svc.create_experiment("test")
        self.svc.end_experiment(exp.experiment_id)
        assert self.svc.get_variant(exp.experiment_id, "user-1") is None
