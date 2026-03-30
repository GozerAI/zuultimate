"""Multi-payment-method support (461)."""
import time
from dataclasses import dataclass, field

@dataclass
class PaymentMethod:
    method_id: str
    tenant_id: str
    method_type: str
    is_default: bool = False
    is_active: bool = True
    label: str = ""
    last_four: str = ""

class PaymentMethodService:
    def __init__(self):
        self._methods = {}
        self._counter = 0

    def add_method(self, tenant_id, method_type, label="", last_four="", is_default=False):
        self._counter += 1
        mid = "pm-{}".format(self._counter)
        if is_default:
            for m in self._methods.values():
                if m.tenant_id == tenant_id: m.is_default = False
        m = PaymentMethod(method_id=mid, tenant_id=tenant_id, method_type=method_type,
                          label=label, last_four=last_four, is_default=is_default)
        self._methods[mid] = m
        return m

    def get_methods(self, tenant_id):
        return [m for m in self._methods.values() if m.tenant_id == tenant_id and m.is_active]

    def set_default(self, method_id):
        m = self._methods.get(method_id)
        if not m: return None
        for x in self._methods.values():
            if x.tenant_id == m.tenant_id: x.is_default = False
        m.is_default = True
        return m

    def remove_method(self, method_id):
        m = self._methods.get(method_id)
        if m: m.is_active = False
        return m

    def get_default(self, tenant_id):
        for m in self._methods.values():
            if m.tenant_id == tenant_id and m.is_default and m.is_active: return m
        return None

payment_method_service = PaymentMethodService()
