"""User engagement scoring (497)."""
import time
import math

class EngagementScoringService:
    WEIGHTS = {"login": 1.0, "api_call": 0.5, "feature_use": 2.0,
               "invite_user": 5.0, "create_project": 3.0, "view_docs": 0.3}

    def __init__(self):
        self._events = {}
        self._scores = {}

    def record_event(self, user_id, tenant_id, event_type, weight_override=None):
        key = "{}:{}".format(tenant_id, user_id)
        if key not in self._events:
            self._events[key] = []
        w = weight_override if weight_override is not None else self.WEIGHTS.get(event_type, 1.0)
        self._events[key].append({"type": event_type, "weight": w, "timestamp": time.time()})

    def compute_score(self, user_id, tenant_id, time_range_seconds=604800):
        key = "{}:{}".format(tenant_id, user_id)
        events = self._events.get(key, [])
        cutoff = time.time() - time_range_seconds
        recent = [e for e in events if e["timestamp"] >= cutoff]
        if not recent:
            return {"user_id": user_id, "score": 0, "level": "inactive", "events_count": 0}
        raw_score = sum(e["weight"] for e in recent)
        recency_bonus = 1.0
        if recent:
            last_event_age = time.time() - recent[-1]["timestamp"]
            recency_bonus = max(0.5, 1.0 - last_event_age / time_range_seconds)
        score = round(min(100, raw_score * recency_bonus), 1)
        if score >= 70: level = "power_user"
        elif score >= 40: level = "active"
        elif score >= 10: level = "casual"
        else: level = "at_risk"
        result = {"user_id": user_id, "score": score, "level": level, "events_count": len(recent)}
        self._scores[key] = result
        return result

    def get_tenant_engagement(self, tenant_id, user_ids):
        results = []
        for uid in user_ids:
            results.append(self.compute_score(uid, tenant_id))
        if not results:
            return {"tenant_id": tenant_id, "avg_score": 0, "users": []}
        avg = sum(r["score"] for r in results) / len(results)
        levels = {}
        for r in results:
            levels[r["level"]] = levels.get(r["level"], 0) + 1
        return {"tenant_id": tenant_id, "avg_score": round(avg, 1),
                "level_distribution": levels, "users": results}

    def get_at_risk_users(self, tenant_id, user_ids, threshold=10):
        return [uid for uid in user_ids
                if self.compute_score(uid, tenant_id)["score"] < threshold]

engagement_scoring_service = EngagementScoringService()
