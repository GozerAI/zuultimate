"""Billing migration tools for plan changes (464)."""
import time
from dataclasses import dataclass, field

@dataclass
class BillingMigration:
    migration_id: str
    tenant_id: str
    from_plan: str
    to_plan: str
    proration_credit: float = 0.0
    new_amount: float = 0.0
    status: str = "pending"

PRICES = {"free": 0, "pro": 29, "growth": 79, "scale": 199}

class BillingMigrationService:
    def __init__(self):
        self._migrations = {}
        self._counter = 0

    def preview_migration(self, from_plan, to_plan, days_used=15, cycle_days=30):
        fp = PRICES.get(from_plan, 0)
        tp = PRICES.get(to_plan, 0)
        credit = round(fp * (cycle_days - days_used) / cycle_days, 2)
        charge = round(tp * (cycle_days - days_used) / cycle_days, 2)
        due = round(charge - credit, 2)
        return {"from_plan": from_plan, "to_plan": to_plan, "unused_credit": credit,
                "new_charge": charge, "amount_due": max(0, due), "credit_back": abs(min(0, due))}

    def execute_migration(self, tenant_id, from_plan, to_plan, days_used=15):
        self._counter += 1
        mid = "bmig-{}".format(self._counter)
        p = self.preview_migration(from_plan, to_plan, days_used)
        m = BillingMigration(migration_id=mid, tenant_id=tenant_id, from_plan=from_plan,
                              to_plan=to_plan, proration_credit=p["unused_credit"],
                              new_amount=p["amount_due"], status="completed")
        self._migrations[mid] = m
        return m

    def get_migrations(self, tenant_id):
        return [m for m in self._migrations.values() if m.tenant_id == tenant_id]

billing_migration_service = BillingMigrationService()
