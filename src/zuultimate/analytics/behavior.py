"""User behavior analytics (474)."""
import time
from dataclasses import dataclass, field

@dataclass
class BehaviorEvent:
    event_id: str
    user_id: str
    tenant_id: str
    event_type: str
    properties: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

class BehaviorAnalyticsService:
    def __init__(self):
        self._events = []
        self._counter = 0

    def track(self, user_id, tenant_id, event_type, properties=None):
        self._counter += 1
        event = BehaviorEvent(event_id="bev-{}".format(self._counter), user_id=user_id,
                              tenant_id=tenant_id, event_type=event_type, properties=properties or {})
        self._events.append(event)
        return event

    def get_user_events(self, user_id, event_type=None, limit=100):
        events = [e for e in self._events if e.user_id == user_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def get_tenant_events(self, tenant_id, event_type=None, limit=1000):
        events = [e for e in self._events if e.tenant_id == tenant_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def get_event_counts(self, tenant_id, time_range_seconds=86400):
        cutoff = time.time() - time_range_seconds
        events = [e for e in self._events if e.tenant_id == tenant_id and e.timestamp >= cutoff]
        counts = {}
        for e in events:
            counts[e.event_type] = counts.get(e.event_type, 0) + 1
        return counts

    def get_active_users(self, tenant_id, time_range_seconds=86400):
        cutoff = time.time() - time_range_seconds
        users = set()
        for e in self._events:
            if e.tenant_id == tenant_id and e.timestamp >= cutoff:
                users.add(e.user_id)
        return list(users)

    def get_user_journey(self, user_id, limit=50):
        events = [e for e in self._events if e.user_id == user_id]
        return [{"event": e.event_type, "timestamp": e.timestamp, "properties": e.properties}
                for e in events[-limit:]]

behavior_analytics_service = BehaviorAnalyticsService()
