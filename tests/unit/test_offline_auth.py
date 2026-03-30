"""Unit tests for offline authentication with cached tokens (item 764)."""

import time
import pytest

from zuultimate.offline.offline_auth import (
    CachedToken,
    OfflineAuthResult,
    OfflineAuthStatus,
    OfflineAuthenticator,
)


class TestOfflineAuthenticator:
    @pytest.fixture
    def auth(self):
        return OfflineAuthenticator(max_cache_age_hours=24, max_cache_entries=100)

    def test_cache_and_validate(self, auth):
        auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                         username="alice", roles=["admin"])
        result = auth.validate("tok1")
        assert result.status == OfflineAuthStatus.VALID
        assert result.user_id == "u1"
        assert result.username == "alice"
        assert result.roles == ["admin"]
        assert result.offline_mode

    def test_cache_miss(self, auth):
        result = auth.validate("unknown-token")
        assert result.status == OfflineAuthStatus.CACHE_MISS

    def test_revoked_token(self, auth):
        auth.cache_token("tok1", user_id="u1", tenant_id="t1", username="alice")
        auth.revoke_token("tok1")
        result = auth.validate("tok1")
        assert result.status == OfflineAuthStatus.REVOKED

    def test_revoke_unknown_token(self, auth):
        assert not auth.revoke_token("nonexistent")

    def test_expired_token(self, auth):
        entry = auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                                 username="alice", expires_at=time.time() - 3600)
        result = auth.validate("tok1")
        assert result.status == OfflineAuthStatus.EXPIRED

    def test_stale_cache(self, auth):
        entry = auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                                 username="alice")
        # Simulate stale cache
        entry.last_verified_online = time.time() - (25 * 3600)
        result = auth.validate("tok1")
        assert result.status == OfflineAuthStatus.EXPIRED
        assert "stale" in result.message.lower()

    def test_refresh_online_check(self, auth):
        entry = auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                                 username="alice")
        entry.last_verified_online = time.time() - (25 * 3600)
        auth.refresh_online_check("tok1")
        result = auth.validate("tok1")
        assert result.status == OfflineAuthStatus.VALID

    def test_refresh_unknown_token(self, auth):
        assert not auth.refresh_online_check("nonexistent")

    def test_evict_expired(self, auth):
        auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                         username="alice", expires_at=time.time() - 3600)
        auth.cache_token("tok2", user_id="u2", tenant_id="t1",
                         username="bob")
        count = auth.evict_expired()
        assert count == 1
        assert auth.cache_size == 1

    def test_cache_eviction_at_capacity(self):
        auth = OfflineAuthenticator(max_cache_entries=3)
        for i in range(4):
            auth.cache_token(f"tok{i}", user_id=f"u{i}", tenant_id="t1",
                             username=f"user{i}")
        assert auth.cache_size == 3

    def test_cache_size(self, auth):
        assert auth.cache_size == 0
        auth.cache_token("tok1", user_id="u1", tenant_id="t1", username="alice")
        assert auth.cache_size == 1

    def test_get_summary(self, auth):
        auth.cache_token("tok1", user_id="u1", tenant_id="t1", username="alice")
        auth.cache_token("tok2", user_id="u2", tenant_id="t1", username="bob",
                         expires_at=time.time() - 100)
        auth.revoke_token("tok1")
        s = auth.get_summary()
        assert s["cache_size"] == 2
        assert s["revoked_count"] == 1
        assert s["expired_count"] >= 1

    def test_metadata(self, auth):
        entry = auth.cache_token("tok1", user_id="u1", tenant_id="t1",
                                 username="alice", metadata={"device": "mobile"})
        assert entry.metadata == {"device": "mobile"}

    def test_cached_token_time_since_online_check_inf(self):
        entry = CachedToken(
            token_hash="h", user_id="u", tenant_id="t",
            username="a", roles=[], issued_at=time.time(),
            expires_at=time.time() + 3600, last_verified_online=0.0,
        )
        assert entry.time_since_online_check == float("inf")

    def test_token_hash_deterministic(self, auth):
        auth.cache_token("tok1", user_id="u1", tenant_id="t1", username="alice")
        result1 = auth.validate("tok1")
        result2 = auth.validate("tok1")
        assert result1.status == result2.status
