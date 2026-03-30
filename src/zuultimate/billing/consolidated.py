"""Consolidated billing for multi-product customers (445)."""
import time
from dataclasses import dataclass, field

@dataclass
class BillingLineItem:
    product: str
    description: str
    amount: float
    quantity: int = 1
    period_start: float = 0.0
    period_end: float = 0.0

@dataclass
class ConsolidatedInvoice:
    invoice_id: str
    tenant_id: str
    line_items: list = field(default_factory=list)
    subtotal: float = 0.0
    tax: float = 0.0
    total: float = 0.0
    status: str = "draft"
    created_at: float = field(default_factory=time.time)

class ConsolidatedBillingService:
    def __init__(self):
        self._invoices = {}
        self._counter = 0

    def create_invoice(self, tenant_id, line_items, tax_rate=0.0):
        self._counter += 1
        iid = "inv-{}".format(self._counter)
        subtotal = sum(item.amount * item.quantity for item in line_items)
        tax = round(subtotal * tax_rate, 2)
        invoice = ConsolidatedInvoice(invoice_id=iid, tenant_id=tenant_id,
                                       line_items=line_items, subtotal=subtotal,
                                       tax=tax, total=round(subtotal + tax, 2))
        self._invoices[iid] = invoice
        return invoice

    def get_invoice(self, invoice_id):
        return self._invoices.get(invoice_id)

    def finalize_invoice(self, invoice_id):
        inv = self._invoices.get(invoice_id)
        if inv and inv.status == "draft":
            inv.status = "finalized"
        return inv

    def get_invoices(self, tenant_id):
        return [i for i in self._invoices.values() if i.tenant_id == tenant_id]

consolidated_billing_service = ConsolidatedBillingService()
