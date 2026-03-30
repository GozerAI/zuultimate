"""Tests for billing modules (442, 445, 449, 452, 455, 458, 461, 464)."""
from zuultimate.billing.stripe_portal import StripePortalService
from zuultimate.billing.consolidated import ConsolidatedBillingService, BillingLineItem
from zuultimate.billing.alerts import BillingAlertService
from zuultimate.billing.api import BillingAPIService
from zuultimate.billing.invoice_customization import InvoiceCustomizationService
from zuultimate.billing.webhook_monitor import WebhookMonitorService
from zuultimate.billing.payment_methods import PaymentMethodService
from zuultimate.billing.migration_tools import BillingMigrationService

class TestStripePortal:
    def test_create_session(self):
        svc = StripePortalService()
        result = svc.create_portal_session("t1", "cus_123", "https://app.example.com")
        assert "url" in result
        assert result["session_id"].startswith("portal-")

    def test_get_portal_url(self):
        svc = StripePortalService()
        url = svc.get_customer_portal_url("t1", "cus_123")
        assert url.startswith("https://billing.stripe.com")

class TestConsolidatedBilling:
    def test_create_invoice(self):
        svc = ConsolidatedBillingService()
        items = [BillingLineItem("zuultimate", "Pro Plan", 29.0),
                 BillingLineItem("trendscope", "Basic", 19.0)]
        inv = svc.create_invoice("t1", items)
        assert inv.subtotal == 48.0
        assert inv.total == 48.0

    def test_invoice_with_tax(self):
        svc = ConsolidatedBillingService()
        items = [BillingLineItem("zuultimate", "Pro Plan", 100.0)]
        inv = svc.create_invoice("t1", items, tax_rate=0.1)
        assert inv.tax == 10.0
        assert inv.total == 110.0

    def test_finalize_invoice(self):
        svc = ConsolidatedBillingService()
        items = [BillingLineItem("zuultimate", "Pro", 29.0)]
        inv = svc.create_invoice("t1", items)
        svc.finalize_invoice(inv.invoice_id)
        assert inv.status == "finalized"

class TestBillingAlerts:
    def test_create_alert(self):
        svc = BillingAlertService()
        a = svc.create_alert("t1", "usage_threshold", threshold=80.0)
        assert a.is_active

    def test_trigger_alert(self):
        svc = BillingAlertService()
        svc.create_alert("t1", "usage_threshold", threshold=80.0)
        triggered = svc.check_and_trigger("t1", "usage_threshold", 90.0)
        assert len(triggered) == 1

    def test_no_trigger_below_threshold(self):
        svc = BillingAlertService()
        svc.create_alert("t1", "usage_threshold", threshold=80.0)
        triggered = svc.check_and_trigger("t1", "usage_threshold", 50.0)
        assert len(triggered) == 0

class TestBillingAPI:
    def test_create_key(self):
        svc = BillingAPIService()
        key = svc.create_api_key("t1")
        assert key.key_id.startswith("bkey-")

    def test_validate_key(self):
        svc = BillingAPIService()
        key = svc.create_api_key("t1", scopes=["billing:read", "billing:write"])
        assert svc.validate_key(key.key_id, "billing:read")
        assert not svc.validate_key(key.key_id, "admin:delete")

    def test_revoke_key(self):
        svc = BillingAPIService()
        key = svc.create_api_key("t1")
        svc.revoke_key(key.key_id)
        assert not svc.validate_key(key.key_id)

class TestInvoiceCustomization:
    def test_set_template(self):
        svc = InvoiceCustomizationService()
        t = svc.set_template("t1", company_name="Acme Corp", currency="EUR")
        assert t.currency == "EUR"

    def test_render_invoice(self):
        svc = InvoiceCustomizationService()
        svc.set_template("t1", company_name="Acme Corp", logo_url="https://acme.com/logo.png")
        result = svc.render_invoice("t1", {"amount": 100})
        assert result["company_name"] == "Acme Corp"

class TestWebhookMonitor:
    def test_record_and_process(self):
        svc = WebhookMonitorService()
        e = svc.record_event("payment.success")
        svc.mark_processed(e.event_id)
        stats = svc.get_stats()
        assert stats["processed"] == 1
        assert stats["success_rate"] == 1.0

    def test_failed_events(self):
        svc = WebhookMonitorService()
        e = svc.record_event("payment.failed")
        svc.mark_failed(e.event_id, "timeout")
        failed = svc.get_failed_events()
        assert len(failed) == 1

class TestPaymentMethods:
    def test_add_method(self):
        svc = PaymentMethodService()
        m = svc.add_method("t1", "card", label="Visa", last_four="4242", is_default=True)
        assert m.is_default

    def test_get_default(self):
        svc = PaymentMethodService()
        svc.add_method("t1", "card", is_default=True)
        assert svc.get_default("t1") is not None

    def test_set_default(self):
        svc = PaymentMethodService()
        m1 = svc.add_method("t1", "card", is_default=True)
        m2 = svc.add_method("t1", "bank_transfer")
        svc.set_default(m2.method_id)
        assert not m1.is_default
        assert m2.is_default

    def test_remove_method(self):
        svc = PaymentMethodService()
        m = svc.add_method("t1", "card", is_default=True)
        svc.remove_method(m.method_id)
        assert not m.is_active
