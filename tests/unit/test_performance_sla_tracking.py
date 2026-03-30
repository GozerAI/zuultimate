"""Tests for API response SLA tracking per endpoint."""

import pytest

from zuultimate.performance.sla_tracking import EndpointSLATracker


class TestEndpointSLATracker:
    """Item #92: API response SLA tracking per endpoint."""

    def test_record_and_percentile(self):
        tracker = EndpointSLATracker()
        for ms in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
            tracker.record("GET /users", ms)
        p50 = tracker.percentile("GET /users", 50)
        assert p50 is not None
        assert 40 <= p50 <= 60

    def test_p99(self):
        tracker = EndpointSLATracker()
        for ms in range(1, 101):
            tracker.record("GET /users", float(ms))
        p99 = tracker.percentile("GET /users", 99)
        assert p99 is not None
        assert p99 >= 90

    def test_empty_endpoint(self):
        tracker = EndpointSLATracker()
        assert tracker.percentile("GET /nope", 50) is None

    def test_sla_compliance_all_ok(self):
        tracker = EndpointSLATracker(sla_target_ms=500.0)
        for _ in range(100):
            tracker.record("GET /fast", 10.0)
        compliance = tracker.sla_compliance("GET /fast")
        assert compliance == 100.0

    def test_sla_compliance_with_violations(self):
        tracker = EndpointSLATracker(sla_target_ms=100.0)
        for _ in range(90):
            tracker.record("GET /mixed", 50.0)
        for _ in range(10):
            tracker.record("GET /mixed", 200.0)
        compliance = tracker.sla_compliance("GET /mixed")
        assert compliance == 90.0

    def test_sla_compliance_no_data(self):
        tracker = EndpointSLATracker()
        assert tracker.sla_compliance("GET /empty") is None

    def test_summary_single(self):
        tracker = EndpointSLATracker(sla_target_ms=500.0)
        tracker.record("GET /test", 100.0)
        summary = tracker.summary("GET /test")
        assert summary["total_requests"] == 1
        assert summary["sla_target_ms"] == 500.0
        assert "p50_ms" in summary
        assert "p95_ms" in summary
        assert "p99_ms" in summary

    def test_summary_all(self):
        tracker = EndpointSLATracker()
        tracker.record("GET /a", 10.0)
        tracker.record("GET /b", 20.0)
        summary = tracker.summary()
        assert "GET /a" in summary
        assert "GET /b" in summary

    def test_window_size_limit(self):
        tracker = EndpointSLATracker(window_size=5)
        for ms in range(100):
            tracker.record("GET /test", float(ms))
        # Only last 5 should be kept
        assert tracker.summary("GET /test")["total_requests"] == 100
        # But percentile is based on windowed data
        p50 = tracker.percentile("GET /test", 50)
        assert p50 is not None
