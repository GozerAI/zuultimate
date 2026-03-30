"""Billing API for third-party integrations (452)."""
import time
from dataclasses import dataclass, field

@dataclass
class BillingAPIKey:
    key_id: str
    tenant_id: str
    key_prefix: str
    scopes: list = field(default_factory=lambda: ["billing:read"])
    is_active: bool = True
    last_used: float = 0.0

class BillingAPIService:
    def __init__(self):
        self._keys = {}
        self._counter = 0

    def create_api_key(self, tenant_id, scopes=None):
        self._counter += 1
        kid = "bkey-{}".format(self._counter)
        key = BillingAPIKey(key_id=kid, tenant_id=tenant_id,
                            key_prefix="bk_{}".format(kid), scopes=scopes or ["billing:read"])
        self._keys[kid] = key
        return key

    def validate_key(self, key_id, required_scope="billing:read"):
        key = self._keys.get(key_id)
        if not key or not key.is_active: return False
        if required_scope not in key.scopes and "*" not in key.scopes: return False
        key.last_used = time.time()
        return True

    def revoke_key(self, key_id):
        key = self._keys.get(key_id)
        if key: key.is_active = False
        return key

    def list_keys(self, tenant_id):
        return [k for k in self._keys.values() if k.tenant_id == tenant_id]

billing_api_service = BillingAPIService()
