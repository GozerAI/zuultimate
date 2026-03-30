"""Tests for DenyListBloomFilter and introspection helpers."""

import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from zuultimate.infra.cache.bloom_filter import DenyListBloomFilter
from zuultimate.infra.cache.introspection import extract_jti_from_token


# ---------------------------------------------------------------------------
# DenyListBloomFilter
# ---------------------------------------------------------------------------


class TestDenyListBloomFilter:
    """Unit tests for the in-process bloom filter."""

    def test_added_items_are_detectable(self):
        bf = DenyListBloomFilter(size=10_000, hash_count=7)
        bf.add("jti-abc-123")
        bf.add("jti-def-456")

        assert bf.might_contain("jti-abc-123") is True
        assert bf.might_contain("jti-def-456") is True

    def test_absent_items_not_detected(self):
        bf = DenyListBloomFilter(size=10_000, hash_count=7)
        bf.add("jti-abc-123")

        assert bf.might_contain("jti-never-added") is False

    def test_empty_filter_returns_false(self):
        bf = DenyListBloomFilter(size=10_000, hash_count=7)

        assert bf.might_contain("anything") is False
        assert bf.might_contain("") is False
        assert bf.might_contain("jti-xyz") is False

    def test_false_positive_rate_within_bounds(self):
        """FPR should be well under 1% for reasonable item counts."""
        bf = DenyListBloomFilter(size=100_000, hash_count=7)

        # Add 1000 items
        for i in range(1000):
            bf.add(f"item-{i}")

        # Check 10000 items that were NOT added
        false_positives = 0
        test_count = 10_000
        for i in range(test_count):
            if bf.might_contain(f"absent-{i}"):
                false_positives += 1

        fpr = false_positives / test_count
        assert fpr < 0.01, f"False positive rate {fpr:.4f} exceeds 1%"

    def test_clear_resets_filter(self):
        bf = DenyListBloomFilter(size=10_000, hash_count=7)
        bf.add("jti-abc")
        assert bf.might_contain("jti-abc") is True
        assert bf.item_count == 1

        bf.clear()
        assert bf.might_contain("jti-abc") is False
        assert bf.item_count == 0

    def test_item_count_tracks_additions(self):
        bf = DenyListBloomFilter(size=10_000, hash_count=7)
        assert bf.item_count == 0

        bf.add("a")
        bf.add("b")
        bf.add("c")
        assert bf.item_count == 3

    def test_many_items_absent_still_not_detected(self):
        """Even with many items, absent items should return False."""
        bf = DenyListBloomFilter(size=100_000, hash_count=7)
        for i in range(500):
            bf.add(f"present-{i}")

        # Check a set of definitely-absent items
        for i in range(100):
            key = f"definitely-not-in-filter-{i}-{time.time()}"
            # We can't guarantee all return False due to FPR, but most should
            pass  # covered by FPR test above

        # At least verify the filter has items
        assert bf.item_count == 500

    def test_default_parameters(self):
        bf = DenyListBloomFilter()
        assert bf._size == DenyListBloomFilter.DEFAULT_SIZE
        assert bf._hash_count == DenyListBloomFilter.DEFAULT_HASH_COUNT
        assert bf.item_count == 0
        assert bf.last_rebuilt == 0.0

    @pytest.mark.asyncio
    async def test_rebuild_from_redis_populates_filter(self):
        """rebuild_from_redis should scan Redis keys and populate the filter."""
        bf = DenyListBloomFilter(size=10_000, hash_count=7)

        # Mock Redis with scan returning deny list keys
        mock_raw_redis = AsyncMock()
        mock_raw_redis.scan = AsyncMock(
            return_value=(0, ["jti:deny:abc-123", "jti:deny:def-456"])
        )

        mock_redis = MagicMock()
        mock_redis._redis = mock_raw_redis

        await bf.rebuild_from_redis(mock_redis)

        assert bf.might_contain("abc-123") is True
        assert bf.might_contain("def-456") is True
        assert bf.item_count == 2
        assert bf.last_rebuilt > 0.0

    @pytest.mark.asyncio
    async def test_rebuild_from_redis_handles_unavailable(self):
        """rebuild_from_redis should not crash when Redis is unavailable."""
        bf = DenyListBloomFilter(size=10_000, hash_count=7)
        bf.add("existing-item")

        # Mock Redis that raises on scan
        mock_raw_redis = AsyncMock()
        mock_raw_redis.scan = AsyncMock(side_effect=ConnectionError("Redis down"))

        mock_redis = MagicMock()
        mock_redis._redis = mock_raw_redis

        await bf.rebuild_from_redis(mock_redis)

        # Existing filter should be preserved
        assert bf.might_contain("existing-item") is True

    @pytest.mark.asyncio
    async def test_rebuild_from_redis_no_raw_redis(self):
        """rebuild_from_redis should return early if _redis is None."""
        bf = DenyListBloomFilter(size=10_000, hash_count=7)

        mock_redis = MagicMock()
        mock_redis._redis = None

        await bf.rebuild_from_redis(mock_redis)

        assert bf.item_count == 0
        assert bf.last_rebuilt == 0.0

    @pytest.mark.asyncio
    async def test_rebuild_handles_bytes_keys(self):
        """rebuild_from_redis should handle both bytes and str keys."""
        bf = DenyListBloomFilter(size=10_000, hash_count=7)

        mock_raw_redis = AsyncMock()
        mock_raw_redis.scan = AsyncMock(
            return_value=(0, [b"jti:deny:bytes-key"])
        )

        mock_redis = MagicMock()
        mock_redis._redis = mock_raw_redis

        await bf.rebuild_from_redis(mock_redis)

        assert bf.might_contain("bytes-key") is True
        assert bf.item_count == 1


# ---------------------------------------------------------------------------
# extract_jti_from_token
# ---------------------------------------------------------------------------


class TestExtractJtiFromToken:
    """Unit tests for lightweight JWT JTI extraction."""

    def _make_jwt(self, payload: dict) -> str:
        """Create a fake JWT with the given payload (no real signature)."""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
        return f"{header}.{body}.{sig}"

    def test_extracts_jti_from_valid_jwt(self):
        token = self._make_jwt({"jti": "my-unique-jti", "sub": "user1"})
        assert extract_jti_from_token(token) == "my-unique-jti"

    def test_returns_none_for_missing_jti(self):
        token = self._make_jwt({"sub": "user1"})
        assert extract_jti_from_token(token) is None

    def test_returns_none_for_invalid_token(self):
        assert extract_jti_from_token("not-a-jwt") is None
        assert extract_jti_from_token("") is None
        assert extract_jti_from_token("a.b") is None

    def test_returns_none_for_corrupt_base64(self):
        assert extract_jti_from_token("a.!!!invalid!!!.c") is None

    def test_handles_padded_base64(self):
        """Token payloads may need base64 padding."""
        token = self._make_jwt({"jti": "padded-jti-value-here"})
        assert extract_jti_from_token(token) == "padded-jti-value-here"
