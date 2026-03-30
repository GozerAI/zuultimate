"""Tests for account health dashboard (354)."""
from zuultimate.enterprise.account_health import AccountHealthService

class TestAccountHealth:
    def setup_method(self):
        self.svc = AccountHealthService()

    def test_compute_health_good(self):
        result = self.svc.compute_health("t1", {"mfa_enabled": True, "active_users": 10,
            "total_users": 10, "no_breaches": True, "payment_current": True})
        assert result["overall_score"] == 100.0

    def test_compute_health_poor(self):
        result = self.svc.compute_health("t1", {"mfa_enabled": False, "active_users": 1,
            "total_users": 10, "no_breaches": False, "payment_current": False})
        assert result["overall_score"] < 50

    def test_recommendations(self):
        result = self.svc.compute_health("t1", {"mfa_enabled": False, "active_users": 1,
            "total_users": 10, "no_breaches": True, "payment_current": True})
        assert len(result["recommendations"]) > 0

    def test_get_health(self):
        self.svc.compute_health("t1", {"mfa_enabled": True, "active_users": 10,
            "total_users": 10, "no_breaches": True, "payment_current": True})
        assert self.svc.get_health("t1") is not None

    def test_health_trend(self):
        self.svc.compute_health("t1", {"mfa_enabled": True, "active_users": 10,
            "total_users": 10, "no_breaches": True, "payment_current": True})
        trend = self.svc.get_health_trend("t1")
        assert trend["current_score"] == 100.0
