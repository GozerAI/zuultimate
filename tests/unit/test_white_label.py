"""Tests for white-label pricing (285)."""
from zuultimate.enterprise.white_label import WhiteLabelService

class TestWhiteLabel:
    def setup_method(self):
        self.svc = WhiteLabelService()

    def test_create_config(self):
        config = self.svc.create_config("r1", "AcmeCorp", domain="acme.com")
        assert config.brand_name == "AcmeCorp"

    def test_get_config(self):
        self.svc.create_config("r1", "AcmeCorp")
        assert self.svc.get_config("r1") is not None

    def test_update_config(self):
        self.svc.create_config("r1", "AcmeCorp")
        updated = self.svc.update_config("r1", brand_name="NewCorp")
        assert updated.brand_name == "NewCorp"

    def test_branded_pricing(self):
        self.svc.create_config("r1", "AcmeCorp", pricing_multiplier=1.5)
        pricing = self.svc.get_branded_pricing("r1")
        assert pricing["plans"]["pro"]["monthly"] == 43.5

    def test_custom_plans(self):
        self.svc.create_config("r1", "AcmeCorp",
            custom_plans={"pro": {"monthly": 39, "name": "Acme Pro"}})
        pricing = self.svc.get_branded_pricing("r1")
        assert pricing["plans"]["pro"]["monthly"] == 39

    def test_list_resellers(self):
        self.svc.create_config("r1", "AcmeCorp")
        self.svc.create_config("r2", "BetaCorp")
        assert len(self.svc.list_resellers()) == 2
