"""Invoice customization per tenant (455)."""
from dataclasses import dataclass, field

@dataclass
class InvoiceTemplate:
    tenant_id: str
    company_name: str = ""
    company_address: str = ""
    logo_url: str = ""
    footer_text: str = ""
    tax_id: str = ""
    currency: str = "USD"
    payment_terms_days: int = 30
    custom_fields: dict = field(default_factory=dict)

class InvoiceCustomizationService:
    def __init__(self):
        self._templates = {}

    def set_template(self, tenant_id, **kwargs):
        t = InvoiceTemplate(tenant_id=tenant_id, **kwargs)
        self._templates[tenant_id] = t
        return t

    def get_template(self, tenant_id):
        return self._templates.get(tenant_id)

    def render_invoice(self, tenant_id, invoice_data):
        t = self._templates.get(tenant_id)
        result = dict(invoice_data)
        if t:
            result.update({"company_name": t.company_name, "logo_url": t.logo_url,
                          "footer_text": t.footer_text, "currency": t.currency})
        return result

invoice_customization_service = InvoiceCustomizationService()
