"""Tests for cancel flow (336, 341, 346)."""
from zuultimate.enterprise.cancel_flow import CancelFlowService

class TestCancelFlow:
    def setup_method(self):
        self.svc = CancelFlowService()

    def test_initiate_cancel(self):
        result = self.svc.initiate_cancel("t1", "too_expensive", feedback="Price too high")
        assert result["status"] == "pending"
        assert result["retention_offer"]

    def test_accept_offer(self):
        result = self.svc.initiate_cancel("t1", "too_expensive")
        req = self.svc.accept_offer(result["request_id"])
        assert req.status == "retained"

    def test_confirm_cancel(self):
        result = self.svc.initiate_cancel("t1", "other")
        req = self.svc.confirm_cancel(result["request_id"])
        assert req.status == "cancelled"

    def test_downgrade_instead(self):
        result = self.svc.initiate_cancel("t1", "too_expensive", current_plan="pro")
        dg = self.svc.downgrade_instead(result["request_id"], "free")
        assert dg["status"] == "downgraded"

    def test_feedback_collected(self):
        self.svc.initiate_cancel("t1", "too_expensive", feedback="Too costly")
        feedback = self.svc.get_feedback("t1")
        assert len(feedback) == 1
        assert feedback[0]["feedback"] == "Too costly"

    def test_retention_stats(self):
        r1 = self.svc.initiate_cancel("t1", "too_expensive")
        self.svc.accept_offer(r1["request_id"])
        r2 = self.svc.initiate_cancel("t2", "other")
        self.svc.confirm_cancel(r2["request_id"])
        stats = self.svc.get_retention_stats()
        assert stats["retained"] == 1
        assert stats["cancelled"] == 1
