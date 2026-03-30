"""Payment webhook reliability monitoring (458)."""
import time
from dataclasses import dataclass, field

@dataclass
class WebhookEvent:
    event_id: str
    event_type: str
    status: str = "received"
    received_at: float = field(default_factory=time.time)
    processed_at: float = 0.0
    retry_count: int = 0
    error: str = ""

class WebhookMonitorService:
    def __init__(self):
        self._events = {}
        self._counter = 0

    def record_event(self, event_type, event_id=None):
        if not event_id:
            self._counter += 1
            event_id = "wh-{}".format(self._counter)
        e = WebhookEvent(event_id=event_id, event_type=event_type)
        self._events[event_id] = e
        return e

    def mark_processed(self, event_id):
        e = self._events.get(event_id)
        if e: e.status = "processed"; e.processed_at = time.time()
        return e

    def mark_failed(self, event_id, error=""):
        e = self._events.get(event_id)
        if e: e.status = "failed"; e.error = error
        return e

    def get_stats(self):
        total = len(self._events)
        processed = sum(1 for e in self._events.values() if e.status == "processed")
        failed = sum(1 for e in self._events.values() if e.status == "failed")
        return {"total": total, "processed": processed, "failed": failed,
                "success_rate": processed / max(total, 1)}

    def get_failed_events(self):
        return [e for e in self._events.values() if e.status == "failed"]

webhook_monitor_service = WebhookMonitorService()
