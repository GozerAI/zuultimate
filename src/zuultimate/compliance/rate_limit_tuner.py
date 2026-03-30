"""Rate limit auto-tuning.

Monitors request patterns and dynamically adjusts rate limits based on
traffic volume, error rates, and abuse signals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TuningStrategy(str, Enum):
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


@dataclass
class RateLimitConfig:
    """Current rate limit configuration for an endpoint."""
    endpoint: str
    max_requests: int
    window_seconds: int
    burst_multiplier: float = 1.5

    @property
    def burst_limit(self) -> int:
        return int(self.max_requests * self.burst_multiplier)


@dataclass
class TrafficSample:
    """A traffic measurement over a time window."""
    endpoint: str
    timestamp: float
    request_count: int
    error_count: int
    rejection_count: int  # 429s served


@dataclass
class TuningRecommendation:
    endpoint: str
    current_limit: int
    recommended_limit: int
    reason: str
    confidence: float  # 0.0 to 1.0


_STRATEGY_MULTIPLIERS: dict[TuningStrategy, dict[str, float]] = {
    TuningStrategy.CONSERVATIVE: {"increase": 1.1, "decrease": 0.8, "error_threshold": 0.01},
    TuningStrategy.BALANCED: {"increase": 1.25, "decrease": 0.75, "error_threshold": 0.05},
    TuningStrategy.AGGRESSIVE: {"increase": 1.5, "decrease": 0.6, "error_threshold": 0.1},
}


class RateLimitTuner:
    """Auto-tunes rate limits based on observed traffic patterns.

    Usage::

        tuner = RateLimitTuner(strategy=TuningStrategy.BALANCED)
        tuner.set_config("/api/v1/login", RateLimitConfig(
            endpoint="/api/v1/login", max_requests=10, window_seconds=300,
        ))
        tuner.record_sample(TrafficSample(
            endpoint="/api/v1/login", timestamp=time.time(),
            request_count=100, error_count=5, rejection_count=20,
        ))
        recommendations = tuner.get_recommendations()
    """

    def __init__(
        self,
        strategy: TuningStrategy = TuningStrategy.BALANCED,
        min_samples: int = 3,
        sample_window: int = 300,
    ) -> None:
        self.strategy = strategy
        self.min_samples = min_samples
        self.sample_window = sample_window
        self._configs: dict[str, RateLimitConfig] = {}
        self._samples: dict[str, list[TrafficSample]] = {}
        self._multipliers = _STRATEGY_MULTIPLIERS[strategy]

    def set_config(self, endpoint: str, config: RateLimitConfig) -> None:
        self._configs[endpoint] = config

    def get_config(self, endpoint: str) -> RateLimitConfig | None:
        return self._configs.get(endpoint)

    def record_sample(self, sample: TrafficSample) -> None:
        if sample.endpoint not in self._samples:
            self._samples[sample.endpoint] = []
        self._samples[sample.endpoint].append(sample)
        # Keep only recent samples
        cutoff = time.time() - (self.sample_window * 10)
        self._samples[sample.endpoint] = [
            s for s in self._samples[sample.endpoint] if s.timestamp > cutoff
        ]

    def get_recommendations(self) -> list[TuningRecommendation]:
        recommendations: list[TuningRecommendation] = []

        for endpoint, config in self._configs.items():
            samples = self._samples.get(endpoint, [])
            if len(samples) < self.min_samples:
                continue

            recent = samples[-self.min_samples:]
            total_requests = sum(s.request_count for s in recent)
            total_errors = sum(s.error_count for s in recent)
            total_rejections = sum(s.rejection_count for s in recent)

            if total_requests == 0:
                continue

            error_rate = total_errors / total_requests
            rejection_rate = total_rejections / total_requests
            error_threshold = self._multipliers["error_threshold"]

            if rejection_rate > 0.3 and error_rate < error_threshold:
                # Too many legitimate requests being rejected
                new_limit = int(config.max_requests * self._multipliers["increase"])
                confidence = min(1.0, rejection_rate)
                recommendations.append(TuningRecommendation(
                    endpoint=endpoint, current_limit=config.max_requests,
                    recommended_limit=new_limit,
                    reason=f"High rejection rate ({rejection_rate:.1%}) with low errors ({error_rate:.1%})",
                    confidence=confidence,
                ))
            elif error_rate > error_threshold:
                # High error rate suggests abuse
                new_limit = int(config.max_requests * self._multipliers["decrease"])
                new_limit = max(1, new_limit)
                confidence = min(1.0, error_rate * 5)
                recommendations.append(TuningRecommendation(
                    endpoint=endpoint, current_limit=config.max_requests,
                    recommended_limit=new_limit,
                    reason=f"High error rate ({error_rate:.1%}) suggests abuse",
                    confidence=confidence,
                ))

        return recommendations

    def apply_recommendations(self, min_confidence: float = 0.5) -> list[TuningRecommendation]:
        """Apply recommendations that meet the confidence threshold."""
        applied: list[TuningRecommendation] = []
        for rec in self.get_recommendations():
            if rec.confidence >= min_confidence and rec.endpoint in self._configs:
                self._configs[rec.endpoint].max_requests = rec.recommended_limit
                applied.append(rec)
        return applied

    def get_summary(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "endpoints_monitored": len(self._configs),
            "endpoints_with_samples": len(self._samples),
            "configs": {
                ep: {"max_requests": c.max_requests, "window_seconds": c.window_seconds}
                for ep, c in self._configs.items()
            },
        }
