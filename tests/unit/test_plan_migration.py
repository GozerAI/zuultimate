"""Tests for plan migration (267) and billing migration (464)."""
from zuultimate.enterprise.plan_migration import PlanMigrationService
from zuultimate.billing.migration_tools import BillingMigrationService

class TestPlanMigration:
    def setup_method(self):
        self.svc = PlanMigrationService()

    def test_calculate_proration_upgrade(self):
        result = self.svc.calculate_proration("free", "pro", days_remaining=15)
        assert result["is_upgrade"]
        assert result["proration_amount"] > 0

    def test_calculate_proration_downgrade(self):
        result = self.svc.calculate_proration("pro", "free", days_remaining=15)
        assert not result["is_upgrade"]

    def test_create_migration(self):
        m = self.svc.create_migration("t1", "free", "pro")
        assert m.status == "pending"
        assert m.migration_id.startswith("mig-")

    def test_complete_migration(self):
        m = self.svc.create_migration("t1", "free", "pro")
        completed = self.svc.complete_migration(m.migration_id)
        assert completed.status == "completed"

    def test_get_migrations(self):
        self.svc.create_migration("t1", "free", "pro")
        self.svc.create_migration("t2", "pro", "growth")
        assert len(self.svc.get_migrations("t1")) == 1
        assert len(self.svc.get_migrations()) == 2

class TestBillingMigration:
    def setup_method(self):
        self.svc = BillingMigrationService()

    def test_preview_upgrade(self):
        p = self.svc.preview_migration("free", "pro", days_used=15)
        assert p["amount_due"] > 0

    def test_preview_downgrade(self):
        p = self.svc.preview_migration("pro", "free", days_used=15)
        assert p["credit_back"] > 0

    def test_execute_migration(self):
        m = self.svc.execute_migration("t1", "free", "pro")
        assert m.status == "completed"
        assert m.migration_id.startswith("bmig-")
