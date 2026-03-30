"""Feature adoption analytics (482)."""
import time

class FeatureAdoptionService:
    def __init__(self):
        self._usage = {}
        self._first_use = {}

    def record_feature_use(self, tenant_id, user_id, feature_key):
        key = "{}:{}:{}".format(tenant_id, user_id, feature_key)
        self._usage[key] = self._usage.get(key, 0) + 1
        if key not in self._first_use:
            self._first_use[key] = time.time()

    def get_adoption_rate(self, tenant_id, feature_key, total_users):
        prefix = "{}:".format(tenant_id)
        users = set()
        for k in self._usage:
            if k.startswith(prefix) and k.endswith(":" + feature_key):
                user_id = k.split(":")[1]
                users.add(user_id)
        adopted = len(users)
        return {"feature": feature_key, "adopted_users": adopted, "total_users": total_users,
                "adoption_rate": adopted / max(total_users, 1)}

    def get_feature_ranking(self, tenant_id):
        prefix = "{}:".format(tenant_id)
        feature_counts = {}
        for k, v in self._usage.items():
            if k.startswith(prefix):
                feature = k.split(":")[-1]
                feature_counts[feature] = feature_counts.get(feature, 0) + v
        ranked = sorted(feature_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"feature": f, "total_uses": c, "rank": i + 1} for i, (f, c) in enumerate(ranked)]

    def get_user_feature_summary(self, tenant_id, user_id):
        prefix = "{}:{}:".format(tenant_id, user_id)
        features = {}
        for k, v in self._usage.items():
            if k.startswith(prefix):
                feature = k.split(":")[-1]
                features[feature] = {"uses": v, "first_use": self._first_use.get(k, 0)}
        return features

feature_adoption_service = FeatureAdoptionService()
