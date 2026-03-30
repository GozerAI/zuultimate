"""Unit tests for automated key rotation scheduling (item 901)."""

import pytest
from datetime import datetime, timedelta, timezone

from zuultimate.compliance.key_rotation_scheduler import (
    KeyRotationScheduler,
    KeyStatus,
    KeyType,
    ManagedKey,
    RotationPlan,
)


def _make_key(key_id="k1", key_type=KeyType.JWT_SIGNING, max_age_days=90,
              age_offset_days=0, status=KeyStatus.ACTIVE):
    created = datetime.now(timezone.utc) - timedelta(days=age_offset_days)
    return ManagedKey(
        key_id=key_id, key_type=key_type, status=status,
        created_at=created, max_age_days=max_age_days,
    )


class TestManagedKey:
    def test_fresh_key_no_rotation(self):
        key = _make_key(age_offset_days=0)
        assert not key.needs_rotation
        assert key.days_until_rotation > 0

    def test_old_key_needs_rotation(self):
        key = _make_key(age_offset_days=100)
        assert key.needs_rotation
        assert key.days_until_rotation == 0.0

    def test_overdue_key(self):
        key = _make_key(age_offset_days=100, max_age_days=90)
        assert key.is_overdue  # 100 > 90 + 7 (grace)

    def test_retired_key_no_rotation(self):
        key = _make_key(age_offset_days=200, status=KeyStatus.RETIRED)
        assert not key.needs_rotation

    def test_compromised_key_no_rotation(self):
        key = _make_key(age_offset_days=200, status=KeyStatus.COMPROMISED)
        assert not key.needs_rotation


class TestKeyRotationScheduler:
    @pytest.fixture
    def scheduler(self):
        return KeyRotationScheduler()

    def test_register_and_get(self, scheduler):
        key = _make_key()
        scheduler.register_key(key)
        assert scheduler.get_key("k1") is key
        assert len(scheduler.all_keys) == 1

    def test_unregister(self, scheduler):
        scheduler.register_key(_make_key())
        assert scheduler.unregister_key("k1")
        assert not scheduler.unregister_key("k1")
        assert scheduler.get_key("k1") is None

    def test_mark_rotated(self, scheduler):
        scheduler.register_key(_make_key(age_offset_days=100))
        scheduler.mark_rotated("k1")
        key = scheduler.get_key("k1")
        assert key.status == KeyStatus.ACTIVE
        assert key.last_rotated_at is not None
        assert not key.needs_rotation

    def test_mark_compromised(self, scheduler):
        scheduler.register_key(_make_key())
        scheduler.mark_compromised("k1")
        assert scheduler.get_key("k1").status == KeyStatus.COMPROMISED

    def test_retire_key(self, scheduler):
        scheduler.register_key(_make_key())
        scheduler.retire_key("k1")
        assert scheduler.get_key("k1").status == KeyStatus.RETIRED

    def test_keys_needing_rotation(self, scheduler):
        scheduler.register_key(_make_key("fresh", age_offset_days=10))
        scheduler.register_key(_make_key("old", age_offset_days=100))
        needing = scheduler.get_keys_needing_rotation()
        assert len(needing) == 1
        assert needing[0].key_id == "old"

    def test_overdue_keys(self, scheduler):
        scheduler.register_key(_make_key("fresh", age_offset_days=10))
        scheduler.register_key(_make_key("overdue", age_offset_days=200))
        overdue = scheduler.get_overdue_keys()
        assert len(overdue) == 1

    def test_compromised_keys(self, scheduler):
        scheduler.register_key(_make_key("k1"))
        scheduler.register_key(_make_key("k2"))
        scheduler.mark_compromised("k1")
        assert len(scheduler.get_compromised_keys()) == 1

    def test_rotation_plan_compromised_urgent(self, scheduler):
        scheduler.register_key(_make_key("k1"))
        scheduler.mark_compromised("k1")
        plans = scheduler.get_rotation_plan()
        assert len(plans) == 1
        assert plans[0].priority == 1
        assert "compromised" in plans[0].reason.lower()

    def test_rotation_plan_overdue(self, scheduler):
        scheduler.register_key(_make_key("old", age_offset_days=200))
        plans = scheduler.get_rotation_plan()
        assert len(plans) == 1
        assert plans[0].priority == 1

    def test_rotation_plan_needs_rotation(self, scheduler):
        scheduler.register_key(_make_key("aging", age_offset_days=91, max_age_days=90))
        plans = scheduler.get_rotation_plan()
        assert len(plans) >= 1

    def test_rotation_plan_empty_for_fresh(self, scheduler):
        scheduler.register_key(_make_key("fresh", age_offset_days=5))
        plans = scheduler.get_rotation_plan()
        assert len(plans) == 0

    def test_rotation_plan_sorted_by_priority(self, scheduler):
        scheduler.register_key(_make_key("aging", age_offset_days=91, max_age_days=90))
        scheduler.register_key(_make_key("compromised"))
        scheduler.mark_compromised("compromised")
        plans = scheduler.get_rotation_plan()
        priorities = [p.priority for p in plans]
        assert priorities == sorted(priorities)

    def test_summary(self, scheduler):
        scheduler.register_key(_make_key("k1"))
        scheduler.register_key(_make_key("k2", age_offset_days=200))
        scheduler.mark_compromised("k2")
        s = scheduler.get_summary()
        assert s["total_keys"] == 2
        assert s["active"] == 1
        assert s["compromised"] == 1
