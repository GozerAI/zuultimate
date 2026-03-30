"""Tests for seat-based licensing (261)."""
import pytest
from zuultimate.enterprise.seat_licensing import SeatLicensingService

class TestSeatLicensing:
    def setup_method(self):
        self.svc = SeatLicensingService()

    def test_create_allocation(self):
        alloc = self.svc.create_allocation("t1", max_seats=10)
        assert alloc.max_seats == 10
        assert alloc.used_seats == 0

    def test_assign_seat(self):
        self.svc.create_allocation("t1", max_seats=5)
        alloc = self.svc.assign_seat("t1", "user-1")
        assert alloc.used_seats == 1

    def test_assign_duplicate_noop(self):
        self.svc.create_allocation("t1", max_seats=5)
        self.svc.assign_seat("t1", "user-1")
        alloc = self.svc.assign_seat("t1", "user-1")
        assert alloc.used_seats == 1

    def test_seat_limit_enforced(self):
        self.svc.create_allocation("t1", max_seats=1)
        self.svc.assign_seat("t1", "user-1")
        with pytest.raises(ValueError, match="Seat limit"):
            self.svc.assign_seat("t1", "user-2")

    def test_overage_allowed(self):
        self.svc.create_allocation("t1", max_seats=1, overage_allowed=True)
        self.svc.assign_seat("t1", "user-1")
        alloc = self.svc.assign_seat("t1", "user-2")
        assert alloc.used_seats == 2

    def test_release_seat(self):
        self.svc.create_allocation("t1", max_seats=5)
        self.svc.assign_seat("t1", "user-1")
        assert self.svc.release_seat("t1", "user-1")
        assert self.svc.get_allocation("t1").used_seats == 0

    def test_resize(self):
        self.svc.create_allocation("t1", max_seats=5)
        alloc = self.svc.resize("t1", 10)
        assert alloc.max_seats == 10

    def test_resize_below_usage_fails(self):
        self.svc.create_allocation("t1", max_seats=5)
        self.svc.assign_seat("t1", "user-1")
        self.svc.assign_seat("t1", "user-2")
        with pytest.raises(ValueError):
            self.svc.resize("t1", 1)

    def test_monthly_cost(self):
        alloc = self.svc.create_allocation("t1", max_seats=10, price_per_seat=15.0)
        assert alloc.monthly_cost == 150.0

    def test_usage_summary(self):
        self.svc.create_allocation("t1", max_seats=10)
        self.svc.assign_seat("t1", "user-1")
        summary = self.svc.get_usage_summary("t1")
        assert summary["used_seats"] == 1
        assert summary["available_seats"] == 9
