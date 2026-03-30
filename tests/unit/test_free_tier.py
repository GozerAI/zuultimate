"""Tests for free tier and upgrade nudges (273)."""
from zuultimate.enterprise.free_tier import FreeTierService, FREE_TIER_LIMITS

class TestFreeTier:
    def setup_method(self):
        self.svc = FreeTierService()

    def test_check_usage_under_limit(self):
        result = self.svc.check_usage("t1", "api_calls_per_day", 50)
        assert not result["at_limit"]
        assert result["pct_used"] == 50.0

    def test_check_usage_at_limit(self):
        result = self.svc.check_usage("t1", "api_calls_per_day", 100)
        assert result["at_limit"]

    def test_nudge_at_80_pct(self):
        result = self.svc.check_usage("t1", "api_calls_per_day", 85)
        assert result["nudge"]
        assert "85" in result["nudge"]

    def test_record_and_get_usage(self):
        self.svc.record_usage("t1", "api_calls_per_day", 5)
        assert self.svc.get_usage("t1", "api_calls_per_day") == 5

    def test_get_all_usage(self):
        self.svc.record_usage("t1", "api_calls_per_day", 50)
        self.svc.record_usage("t1", "storage_mb", 30)
        usage = self.svc.get_all_usage("t1")
        assert "api_calls_per_day" in usage
        assert "storage_mb" in usage

    def test_reset_daily(self):
        self.svc.record_usage("t1", "api_calls_per_day", 50)
        self.svc.reset_daily_usage("t1")
        assert self.svc.get_usage("t1", "api_calls_per_day") == 0

    def test_get_upgrade_nudges(self):
        self.svc.record_usage("t1", "api_calls_per_day", 90)
        nudges = self.svc.get_upgrade_nudges("t1")
        assert len(nudges) > 0
