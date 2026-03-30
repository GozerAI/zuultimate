"""Aggregate risk signals into a composite score and action decision."""

from zuultimate.common.metrics import RISK_DECISIONS_TOTAL
from zuultimate.common.redis import RedisManager
from zuultimate.identity.risk.models import RiskAction, RiskDecision, RiskSignal
from zuultimate.identity.risk.signals import (
    GeoAnomalySignal,
    NewDeviceSignal,
    VelocitySignal,
)


class RiskEvaluator:
    """Combine multiple risk signals into a single decision.

    Score thresholds (based on the max individual signal score):
    - score > 0.85 -> block + audit event
    - score > 0.6  -> step_up MFA
    - otherwise     -> allow
    """

    def __init__(self, redis: RedisManager):
        self.signals = [
            VelocitySignal(redis),
            NewDeviceSignal(redis),
            GeoAnomalySignal(redis),
        ]

    async def evaluate(self, context: dict) -> RiskDecision:
        """Evaluate all signal generators and return a composite decision."""
        results: list[RiskSignal] = []
        for signal in self.signals:
            result = await signal.evaluate(context)
            if result.score > 0.0:
                results.append(result)

        composite = max((s.score for s in results), default=0.0)

        if composite > 0.85:
            action = RiskAction.block
        elif composite > 0.6:
            action = RiskAction.step_up
        else:
            action = RiskAction.allow

        RISK_DECISIONS_TOTAL.labels(action=action.value).inc()
        return RiskDecision(action=action, score=composite, signals=results)
