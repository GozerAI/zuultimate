"""Billing alert system (449)."""
import time
from dataclasses import dataclass, field

@dataclass
class BillingAlert:
    alert_id: str
    tenant_id: str
    alert_type: str  # usage_threshold, payment_failed, invoice_due, overage
    threshold: float = 0.0
    message: str = ""
    is_active: bool = True
    triggered_at: float = 0.0
    created_at: float = field(default_factory=time.time)

class BillingAlertService:
    def __init__(self):
        self._alerts = {}
        self._history = []
        self._counter = 0

    def create_alert(self, tenant_id, alert_type, threshold=0.0, message=""):
        self._counter += 1
        aid = "alert-{}".format(self._counter)
        alert = BillingAlert(alert_id=aid, tenant_id=tenant_id, alert_type=alert_type,
                             threshold=threshold, message=message)
        self._alerts[aid] = alert
        return alert

    def check_and_trigger(self, tenant_id, metric_type, current_value):
        triggered = []
        for a in self._alerts.values():
            if a.tenant_id == tenant_id and a.alert_type == metric_type and a.is_active:
                if current_value >= a.threshold:
                    a.triggered_at = time.time()
                    triggered.append(a)
                    self._history.append({"alert_id": a.alert_id, "tenant_id": tenant_id,
                                         "value": current_value, "threshold": a.threshold,
                                         "triggered_at": a.triggered_at})
        return triggered

    def get_alerts(self, tenant_id):
        return [a for a in self._alerts.values() if a.tenant_id == tenant_id]

    def get_history(self, tenant_id):
        return [h for h in self._history if h["tenant_id"] == tenant_id]

    def deactivate_alert(self, alert_id):
        a = self._alerts.get(alert_id)
        if a: a.is_active = False
        return a

billing_alert_service = BillingAlertService()
