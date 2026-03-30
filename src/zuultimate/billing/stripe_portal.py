"""Stripe Customer Portal integration (442)."""
import time
from dataclasses import dataclass, field

@dataclass
class PortalSession:
    session_id: str
    tenant_id: str
    customer_id: str
    return_url: str = ""
    created_at: float = field(default_factory=time.time)
    url: str = ""

class StripePortalService:
    def __init__(self):
        self._sessions = {}
        self._counter = 0

    def create_portal_session(self, tenant_id, customer_id, return_url=""):
        self._counter += 1
        sid = "portal-{}".format(self._counter)
        url = "https://billing.stripe.com/p/session/{}".format(sid)
        session = PortalSession(session_id=sid, tenant_id=tenant_id,
                                customer_id=customer_id, return_url=return_url, url=url)
        self._sessions[sid] = session
        return {"session_id": sid, "url": url, "return_url": return_url}

    def get_session(self, session_id):
        return self._sessions.get(session_id)

    def get_customer_portal_url(self, tenant_id, customer_id, return_url=""):
        result = self.create_portal_session(tenant_id, customer_id, return_url)
        return result["url"]

stripe_portal_service = StripePortalService()
