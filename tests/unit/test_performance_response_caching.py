"""Tests for API response caching with Vary headers."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from starlette.testclient import TestClient

from zuultimate.performance.response_caching import ResponseCache, ResponseCacheMiddleware


class _FakeHeaders(dict):
    """Dict subclass that works like Starlette Headers."""
    pass


def _make_request(method="GET", path="/test", headers=None):
    """Create a mock Starlette Request."""
    mock = MagicMock()
    mock.method = method
    mock.url.path = path
    mock.query_params = {}
    mock.headers = _FakeHeaders(headers or {})
    return mock


class TestResponseCache:
    """Item #85: API response caching with Vary headers."""

    def test_cache_get_response(self):
        cache = ResponseCache(ttl=60.0)
        req = _make_request()
        cache.put(req, 200, {"data": "test"})
        result = cache.get(req)
        assert result is not None
        assert result["body"] == {"data": "test"}
        assert result["status_code"] == 200

    def test_miss_returns_none(self):
        cache = ResponseCache()
        req = _make_request(path="/other")
        assert cache.get(req) is None

    def test_post_not_cached(self):
        cache = ResponseCache()
        req = _make_request(method="POST")
        cache.put(req, 200, {"data": "test"})
        assert cache.get(req) is None

    def test_error_not_cached(self):
        cache = ResponseCache()
        req = _make_request()
        cache.put(req, 500, {"error": "fail"})
        assert cache.get(req) is None

    def test_vary_by_authorization(self):
        cache = ResponseCache()
        req1 = _make_request(headers={"Authorization": "Bearer t1"})
        req2 = _make_request(headers={"Authorization": "Bearer t2"})

        cache.put(req1, 200, {"user": "u1"})
        assert cache.get(req1) is not None
        assert cache.get(req2) is None  # Different auth = different cache key

    def test_stats(self):
        cache = ResponseCache()
        req = _make_request()
        cache.put(req, 200, {"data": "test"})
        cache.get(req)  # hit
        cache.get(_make_request(path="/other"))  # miss
        stats = cache.stats
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1

    def test_custom_vary_headers(self):
        cache = ResponseCache()
        cache.vary_headers = ["Accept-Language"]
        assert cache.vary_headers == ["Accept-Language"]
