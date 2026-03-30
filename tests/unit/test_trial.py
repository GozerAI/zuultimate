"""Tests for trial system (366, 371, 375, 379, 384, 388, 392)."""
from zuultimate.enterprise.trial import TrialService, PROGRESSIVE_UNLOCK_SCHEDULE

class TestTrial:
    def setup_method(self):
        self.svc = TrialService()

    def test_create_trial(self):
        t = self.svc.create_trial("t1")
        assert t.is_active
        assert t.plan == "scale"

    def test_check_trial_active(self):
        self.svc.create_trial("t1")
        assert self.svc.check_trial_active("t1") is not None

    def test_no_active_trial(self):
        assert self.svc.check_trial_active("t1") is None

    def test_progressive_unlock(self):
        t = self.svc.create_trial("t1")
        features = self.svc.get_unlocked_features(t.trial_id)
        assert "basic_auth" in features

    def test_record_usage(self):
        t = self.svc.create_trial("t1")
        self.svc.record_usage(t.trial_id, "basic_auth")
        assert len(t.usage_events) == 1

    def test_usage_summary(self):
        t = self.svc.create_trial("t1")
        self.svc.record_usage(t.trial_id, "basic_auth")
        self.svc.record_usage(t.trial_id, "sso_oidc")
        summary = self.svc.get_usage_summary(t.trial_id)
        assert summary["unique_features_used"] == 2

    def test_social_proof(self):
        self.svc.create_trial("t1")
        self.svc.create_trial("t2")
        proof = self.svc.get_social_proof()
        assert proof["signups_today"] == 2

    def test_one_click_signup(self):
        t = self.svc.create_trial("t1", signup_method="one_click")
        assert t.signup_method == "one_click"

    def test_personalization(self):
        t = self.svc.create_trial("t1", personalization={"industry": "fintech"})
        assert t.personalization["industry"] == "fintech"

    def test_sso_first_enterprise(self):
        t = self.svc.create_trial("t1", signup_method="sso")
        assert t.signup_method == "sso"

    def test_end_trial(self):
        t = self.svc.create_trial("t1")
        self.svc.end_trial(t.trial_id)
        assert not t.is_active
