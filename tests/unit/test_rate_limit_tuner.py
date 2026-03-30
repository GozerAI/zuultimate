"""Unit tests for rate limit auto-tuning (item 940)."""

import time
import pytest

from zuultimate.compliance.rate_limit_tuner import (
    RateLimitConfig,
    RateLimitTuner,
    TrafficSample,
    TuningRecommendation,
    TuningStrategy,
)


def _sample(endpoint, requests=100, errors=0, rejections=0):
    return TrafficSample(
        endpoint=endpoint, timestamp=time.time(),
        request_count=requests, error_count=errors, rejection_count=rejections,
    )


class TestRateLimitConfig:
    def test_burst_limit(self):
        config = RateLimitConfig(endpoint="/api", max_requests=100, window_seconds=60)
        assert config.burst_limit == 150

    def test_custom_burst_multiplier(self):
        config = RateLimitConfig(endpoint="/api", max_requests=100,
                                 window_seconds=60, burst_multiplier=2.0)
        assert config.burst_limit == 200


class TestRateLimitTuner:
    @pytest.fixture
    def tuner(self):
        t = RateLimitTuner(strategy=TuningStrategy.BALANCED, min_samples=3)
        t.set_config("/api/login", RateLimitConfig(
            endpoint="/api/login", max_requests=10, window_seconds=300,
        ))
        return t

    def test_no_recommendations_without_samples(self, tuner):
        assert len(tuner.get_recommendations()) == 0

    def test_no_recommendations_insufficient_samples(self, tuner):
        tuner.record_sample(_sample("/api/login"))
        tuner.record_sample(_sample("/api/login"))
        assert len(tuner.get_recommendations()) == 0

    def test_recommend_increase_high_rejection(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=0, rejections=40))
        recs = tuner.get_recommendations()
        assert len(recs) == 1
        assert recs[0].recommended_limit > 10

    def test_recommend_decrease_high_errors(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=10, rejections=0))
        recs = tuner.get_recommendations()
        assert len(recs) == 1
        assert recs[0].recommended_limit < 10

    def test_no_recommendation_normal_traffic(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=1, rejections=5))
        recs = tuner.get_recommendations()
        assert len(recs) == 0

    def test_apply_recommendations(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=0, rejections=40))
        applied = tuner.apply_recommendations(min_confidence=0.0)
        assert len(applied) >= 1
        new_config = tuner.get_config("/api/login")
        assert new_config.max_requests > 10

    def test_apply_recommendations_confidence_filter(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=0, rejections=40))
        applied = tuner.apply_recommendations(min_confidence=2.0)
        assert len(applied) == 0

    def test_conservative_strategy(self):
        tuner = RateLimitTuner(strategy=TuningStrategy.CONSERVATIVE, min_samples=3)
        tuner.set_config("/api", RateLimitConfig(endpoint="/api", max_requests=100, window_seconds=60))
        for _ in range(5):
            tuner.record_sample(_sample("/api", requests=100, errors=0, rejections=40))
        recs = tuner.get_recommendations()
        if recs:
            assert recs[0].recommended_limit <= 110  # conservative increase

    def test_aggressive_strategy(self):
        tuner = RateLimitTuner(strategy=TuningStrategy.AGGRESSIVE, min_samples=3)
        tuner.set_config("/api", RateLimitConfig(endpoint="/api", max_requests=100, window_seconds=60))
        for _ in range(5):
            tuner.record_sample(_sample("/api", requests=100, errors=0, rejections=40))
        recs = tuner.get_recommendations()
        if recs:
            assert recs[0].recommended_limit >= 150

    def test_get_summary(self, tuner):
        tuner.record_sample(_sample("/api/login"))
        s = tuner.get_summary()
        assert s["strategy"] == "balanced"
        assert s["endpoints_monitored"] == 1
        assert s["endpoints_with_samples"] == 1

    def test_set_and_get_config(self, tuner):
        config = tuner.get_config("/api/login")
        assert config is not None
        assert config.max_requests == 10

    def test_zero_requests_skipped(self, tuner):
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=0, errors=0, rejections=0))
        assert len(tuner.get_recommendations()) == 0

    def test_old_samples_pruned(self, tuner):
        old_sample = TrafficSample(
            endpoint="/api/login", timestamp=time.time() - 999999,
            request_count=100, error_count=50, rejection_count=50,
        )
        tuner.record_sample(old_sample)
        # Record fresh samples
        for _ in range(5):
            tuner.record_sample(_sample("/api/login", requests=100, errors=1, rejections=1))
        # Old sample should be pruned
        recs = tuner.get_recommendations()
        assert len(recs) == 0  # fresh traffic is normal

    def test_decrease_limit_never_below_one(self):
        tuner = RateLimitTuner(strategy=TuningStrategy.AGGRESSIVE, min_samples=3)
        tuner.set_config("/api", RateLimitConfig(endpoint="/api", max_requests=1, window_seconds=60))
        for _ in range(5):
            tuner.record_sample(_sample("/api", requests=100, errors=50, rejections=0))
        recs = tuner.get_recommendations()
        if recs:
            assert recs[0].recommended_limit >= 1
