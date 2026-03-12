"""Individual risk signal generators for auth risk evaluation.

Each generator examines one dimension of risk and returns a RiskSignal with a
score between 0.0 (no risk) and 1.0 (maximum risk).  All inputs are pre-hashed
-- no PII reaches this layer.
"""

from zuultimate.common.redis import RedisManager
from zuultimate.identity.risk.models import RiskSignal

_VELOCITY_WINDOW = 60  # seconds
_VELOCITY_THRESHOLD = 5
_VELOCITY_BLOCK_THRESHOLD = 15
_DEVICE_TTL = 30 * 86400  # 30 days
_GEO_TTL = 90 * 86400  # 90 days


class VelocitySignal:
    """Detect abnormal auth-attempt frequency from the same IP.

    Graduated scoring:
    - > 5 attempts in 60 s  -> 0.7 (step-up level)
    - > 15 attempts in 60 s -> 0.9 (block level)
    """

    def __init__(self, redis: RedisManager):
        self.redis = redis

    async def evaluate(self, context: dict) -> RiskSignal:
        ip_hash = context.get("ip_hash", "")
        key = f"risk:velocity:{ip_hash}"
        count = await self.redis.sliding_window_add(key, _VELOCITY_WINDOW)

        if count > _VELOCITY_BLOCK_THRESHOLD:
            return RiskSignal(
                signal_type="velocity",
                score=0.9,
                evidence={"count": count, "window": _VELOCITY_WINDOW},
            )
        if count > _VELOCITY_THRESHOLD:
            return RiskSignal(
                signal_type="velocity",
                score=0.7,
                evidence={"count": count, "window": _VELOCITY_WINDOW},
            )
        return RiskSignal(signal_type="velocity", score=0.0)


class NewDeviceSignal:
    """Flag first-time device fingerprints not seen in the last 30 days."""

    def __init__(self, redis: RedisManager):
        self.redis = redis

    async def evaluate(self, context: dict) -> RiskSignal:
        user_hash = context.get("user_hash", "")
        device_hash = context.get("device_hash", "")
        key = f"risk:device:{user_hash}:{device_hash}"

        existing = await self.redis.get(key)
        # Always refresh the TTL on successful auth
        await self.redis.setex(key, _DEVICE_TTL, "1")

        if existing is None:
            return RiskSignal(
                signal_type="new_device",
                score=0.4,
                evidence={"device_hash": device_hash[:8]},
            )
        return RiskSignal(signal_type="new_device", score=0.0)


class GeoAnomalySignal:
    """Flag auth attempts from countries not seen in the last 90 days."""

    def __init__(self, redis: RedisManager):
        self.redis = redis

    async def evaluate(self, context: dict) -> RiskSignal:
        user_hash = context.get("user_hash", "")
        country_code = context.get("country_code", "unknown")
        key = f"risk:geo:{user_hash}:{country_code}"

        existing = await self.redis.get(key)
        # Always refresh the TTL on successful auth
        await self.redis.setex(key, _GEO_TTL, "1")

        if existing is None:
            return RiskSignal(
                signal_type="geo_anomaly",
                score=0.5,
                evidence={"country_code": country_code},
            )
        return RiskSignal(signal_type="geo_anomaly", score=0.0)
