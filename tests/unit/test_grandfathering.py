"""Tests for pricing grandfathering (288)."""
from zuultimate.enterprise.grandfathering import GrandfatheringService

class TestGrandfathering:
    def setup_method(self):
        self.svc = GrandfatheringService()

    def test_create_clause(self):
        c = self.svc.create_clause("t1", "pro", 29.0, lock_months=12)
        assert c.original_price == 29.0

    def test_check_grandfathered(self):
        self.svc.create_clause("t1", "pro", 29.0)
        assert self.svc.check_grandfathered("t1") is not None

    def test_not_grandfathered(self):
        assert self.svc.check_grandfathered("t1") is None

    def test_effective_price_grandfathered(self):
        self.svc.create_clause("t1", "pro", 19.0)
        assert self.svc.get_effective_price("t1", 29.0) == 19.0

    def test_effective_price_no_clause(self):
        assert self.svc.get_effective_price("t1", 29.0) == 29.0

    def test_expire_clause(self):
        c = self.svc.create_clause("t1", "pro", 19.0)
        self.svc.expire_clause(c.clause_id)
        assert self.svc.check_grandfathered("t1") is None
