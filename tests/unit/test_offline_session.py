"""Unit tests for offline session management (item 776)."""

import time
import pytest

from zuultimate.offline.offline_session import (
    OfflineSession,
    OfflineSessionManager,
    OfflineSessionState,
    SessionSyncResult,
)


class TestOfflineSessionManager:
    @pytest.fixture
    def mgr(self):
        return OfflineSessionManager(
            idle_timeout_minutes=30,
            absolute_timeout_hours=24,
            max_sessions_per_user=3,
            max_total_sessions=100,
        )

    def test_create_session(self, mgr):
        session = mgr.create_session("u1", "t1", ip_address="1.2.3.4")
        assert session.user_id == "u1"
        assert session.tenant_id == "t1"
        assert session.state == OfflineSessionState.ACTIVE
        assert session.ip_address == "1.2.3.4"

    def test_get_session(self, mgr):
        created = mgr.create_session("u1", "t1")
        fetched = mgr.get_session(created.session_id)
        assert fetched is not None
        assert fetched.session_id == created.session_id

    def test_get_nonexistent(self, mgr):
        assert mgr.get_session("nope") is None

    def test_touch_updates_activity(self, mgr):
        session = mgr.create_session("u1", "t1")
        old_activity = session.last_activity
        time.sleep(0.01)
        assert mgr.touch(session.session_id)
        assert session.last_activity > old_activity

    def test_touch_expired_returns_false(self, mgr):
        session = mgr.create_session("u1", "t1")
        session.expires_at = time.time() - 100
        assert not mgr.touch(session.session_id)

    def test_invalidate(self, mgr):
        session = mgr.create_session("u1", "t1")
        assert mgr.invalidate(session.session_id)
        assert session.state == OfflineSessionState.INVALIDATED

    def test_invalidate_nonexistent(self, mgr):
        assert not mgr.invalidate("nope")

    def test_invalidate_user_sessions(self, mgr):
        mgr.create_session("u1", "t1")
        mgr.create_session("u1", "t1")
        mgr.create_session("u2", "t1")
        count = mgr.invalidate_user_sessions("u1")
        assert count == 2

    def test_mark_for_sync(self, mgr):
        session = mgr.create_session("u1", "t1")
        assert mgr.mark_for_sync(session.session_id)
        assert session.state == OfflineSessionState.PENDING_SYNC
        assert session.needs_sync

    def test_mark_synced(self, mgr):
        session = mgr.create_session("u1", "t1")
        mgr.mark_for_sync(session.session_id)
        assert mgr.mark_synced(session.session_id)
        assert session.state == OfflineSessionState.SYNCED

    def test_get_pending_sync(self, mgr):
        s1 = mgr.create_session("u1", "t1")
        s2 = mgr.create_session("u2", "t1")
        mgr.mark_for_sync(s1.session_id)
        pending = mgr.get_pending_sync()
        assert len(pending) == 1
        assert pending[0].session_id == s1.session_id

    def test_cleanup_expired(self, mgr):
        s1 = mgr.create_session("u1", "t1")
        s1.expires_at = time.time() - 100
        s2 = mgr.create_session("u2", "t1")
        count = mgr.cleanup_expired()
        assert count == 1
        assert mgr.get_session(s1.session_id).state == OfflineSessionState.EXPIRED

    def test_purge_inactive(self, mgr):
        s1 = mgr.create_session("u1", "t1")
        s2 = mgr.create_session("u2", "t1")
        mgr.invalidate(s1.session_id)
        count = mgr.purge_inactive()
        assert count == 1
        assert mgr.get_session(s1.session_id) is None
        assert mgr.get_session(s2.session_id) is not None

    def test_max_sessions_per_user_eviction(self, mgr):
        sessions = []
        for i in range(3):
            sessions.append(mgr.create_session("u1", "t1"))
        # 4th should evict oldest
        s4 = mgr.create_session("u1", "t1")
        assert mgr.get_active_count("u1") <= 3

    def test_max_total_sessions_eviction(self):
        mgr = OfflineSessionManager(max_total_sessions=3)
        for i in range(4):
            mgr.create_session(f"u{i}", "t1")
        total = sum(1 for _ in mgr._sessions.values())
        assert total <= 3

    def test_get_active_count(self, mgr):
        mgr.create_session("u1", "t1")
        mgr.create_session("u1", "t1")
        mgr.create_session("u2", "t1")
        assert mgr.get_active_count("u1") == 2
        assert mgr.get_active_count() == 3

    def test_get_summary(self, mgr):
        mgr.create_session("u1", "t1")
        s2 = mgr.create_session("u2", "t1")
        mgr.invalidate(s2.session_id)
        s = mgr.get_summary()
        assert s["total_sessions"] == 2
        assert s["active"] == 1
        assert s["invalidated"] == 1
        assert s["idle_timeout_minutes"] == 30

    def test_access_log(self, mgr):
        session = mgr.create_session("u1", "t1")
        mgr.touch(session.session_id)
        assert len(session.access_log) >= 2
        assert session.access_log[0]["action"] == "created"
        assert session.access_log[1]["action"] == "touch"

    def test_session_properties(self, mgr):
        session = mgr.create_session("u1", "t1")
        assert session.age_seconds >= 0
        assert session.idle_seconds >= 0
        assert not session.is_expired
        assert not session.needs_sync

    def test_metadata(self, mgr):
        session = mgr.create_session("u1", "t1", metadata={"source": "mobile"})
        assert session.metadata == {"source": "mobile"}
