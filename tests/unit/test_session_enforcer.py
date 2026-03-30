"""Unit tests for automated session security enforcement (item 913)."""

import pytest
from datetime import datetime, timedelta, timezone

from zuultimate.compliance.session_enforcer import (
    SessionEnforcer,
    SessionPolicy,
    SessionRecord,
    SessionViolation,
    SessionViolationType,
)


def _make_session(session_id="s1", user_id="u1", tenant_id="t1",
                  age_hours=0, idle_minutes=0, ip_history=None):
    now = datetime.now(timezone.utc)
    return SessionRecord(
        session_id=session_id, user_id=user_id, tenant_id=tenant_id,
        created_at=now - timedelta(hours=age_hours),
        last_activity=now - timedelta(minutes=idle_minutes),
        device_fingerprint="fp-abc", ip_address="1.2.3.4",
        ip_history=ip_history or [],
    )


class TestSessionEnforcer:
    @pytest.fixture
    def enforcer(self):
        return SessionEnforcer(SessionPolicy(
            max_concurrent_sessions=3,
            idle_timeout_minutes=30,
            absolute_timeout_hours=24,
            allowed_ip_change_count=3,
        ))

    def test_register_session(self, enforcer):
        session = _make_session()
        violations = enforcer.register_session(session)
        assert len(violations) == 0
        assert enforcer.get_active_session_count("u1") == 1

    def test_max_concurrent_exceeded(self, enforcer):
        for i in range(3):
            enforcer.register_session(_make_session(session_id=f"s{i}"))
        violations = enforcer.register_session(_make_session(session_id="s3"))
        assert len(violations) == 1
        assert violations[0].violation_type == SessionViolationType.MAX_CONCURRENT_EXCEEDED

    def test_idle_timeout(self, enforcer):
        session = _make_session(idle_minutes=45)
        enforcer.register_session(session)
        violations = enforcer.check_session("s1")
        types = [v.violation_type for v in violations]
        assert SessionViolationType.IDLE_TIMEOUT in types

    def test_absolute_timeout(self, enforcer):
        session = _make_session(age_hours=25)
        enforcer.register_session(session)
        violations = enforcer.check_session("s1")
        types = [v.violation_type for v in violations]
        assert SessionViolationType.ABSOLUTE_TIMEOUT in types

    def test_ip_change_violation(self, enforcer):
        session = _make_session(ip_history=["a", "b", "c", "d"])
        enforcer.register_session(session)
        violations = enforcer.check_session("s1")
        types = [v.violation_type for v in violations]
        assert SessionViolationType.IP_CHANGE in types

    def test_no_violations_clean_session(self, enforcer):
        session = _make_session(age_hours=1, idle_minutes=5)
        enforcer.register_session(session)
        assert len(enforcer.check_session("s1")) == 0

    def test_check_nonexistent_session(self, enforcer):
        assert enforcer.check_session("nonexistent") == []

    def test_update_activity(self, enforcer):
        session = _make_session()
        enforcer.register_session(session)
        enforcer.update_activity("s1", ip_address="5.6.7.8")
        s = enforcer._sessions["s1"]
        assert s.ip_address == "5.6.7.8"
        assert "1.2.3.4" in s.ip_history

    def test_update_activity_same_ip(self, enforcer):
        session = _make_session()
        enforcer.register_session(session)
        enforcer.update_activity("s1", ip_address="1.2.3.4")
        assert len(enforcer._sessions["s1"].ip_history) == 0

    def test_terminate_session(self, enforcer):
        enforcer.register_session(_make_session())
        assert enforcer.terminate_session("s1")
        assert not enforcer.terminate_session("s1")
        assert enforcer.get_active_session_count("u1") == 0

    def test_terminate_user_sessions(self, enforcer):
        enforcer.register_session(_make_session("s1"))
        enforcer.register_session(_make_session("s2"))
        enforcer.register_session(_make_session("s3", user_id="u2"))
        count = enforcer.terminate_user_sessions("u1")
        assert count == 2
        assert enforcer.get_active_session_count("u1") == 0
        assert enforcer.get_active_session_count("u2") == 1

    def test_cleanup_expired(self, enforcer):
        enforcer.register_session(_make_session("s1", age_hours=25))
        enforcer.register_session(_make_session("s2", idle_minutes=45))
        enforcer.register_session(_make_session("s3", age_hours=1))
        count = enforcer.cleanup_expired()
        assert count == 2

    def test_default_policy(self):
        enforcer = SessionEnforcer()
        assert enforcer.policy.max_concurrent_sessions == 5
        assert enforcer.policy.idle_timeout_minutes == 30
        assert enforcer.policy.absolute_timeout_hours == 24
