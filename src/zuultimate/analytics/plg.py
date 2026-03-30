"""Product-led growth analytics (490)."""
import time

class PLGAnalyticsService:
    def __init__(self):
        self._funnels = {}
        self._conversions = []

    def track_funnel_step(self, user_id, funnel_name, step_name):
        key = "{}:{}".format(funnel_name, user_id)
        if key not in self._funnels:
            self._funnels[key] = {"user_id": user_id, "funnel": funnel_name, "steps": [], "started_at": time.time()}
        self._funnels[key]["steps"].append({"step": step_name, "timestamp": time.time()})

    def track_conversion(self, user_id, from_plan, to_plan, revenue=0):
        self._conversions.append({"user_id": user_id, "from_plan": from_plan, "to_plan": to_plan,
                                  "revenue": revenue, "timestamp": time.time()})

    def get_funnel_analysis(self, funnel_name):
        entries = {k: v for k, v in self._funnels.items() if v["funnel"] == funnel_name}
        if not entries:
            return {"funnel": funnel_name, "total_users": 0, "steps": {}}
        step_counts = {}
        for entry in entries.values():
            for s in entry["steps"]:
                step_counts[s["step"]] = step_counts.get(s["step"], 0) + 1
        total = len(entries)
        return {"funnel": funnel_name, "total_users": total,
                "steps": {s: {"count": c, "rate": c / total} for s, c in step_counts.items()}}

    def get_conversion_metrics(self, time_range_seconds=2592000):
        cutoff = time.time() - time_range_seconds
        recent = [c for c in self._conversions if c["timestamp"] >= cutoff]
        total_revenue = sum(c["revenue"] for c in recent)
        return {"total_conversions": len(recent), "total_revenue": total_revenue,
                "avg_revenue": total_revenue / max(len(recent), 1)}

    def get_activation_rate(self, funnel_name, activation_step):
        entries = {k: v for k, v in self._funnels.items() if v["funnel"] == funnel_name}
        if not entries: return 0.0
        activated = sum(1 for e in entries.values() if any(s["step"] == activation_step for s in e["steps"]))
        return activated / len(entries)

plg_analytics_service = PLGAnalyticsService()
