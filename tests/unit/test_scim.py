"""Tests for SCIM user provisioning (397)."""
from zuultimate.enterprise.scim import SCIMService

class TestSCIM:
    def setup_method(self):
        self.svc = SCIMService()

    def test_create_user(self):
        u = self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        assert u.scim_id.startswith("scim-")
        assert u.active

    def test_find_by_external_id(self):
        self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        u = self.svc.find_by_external_id("ext-1", "t1")
        assert u is not None

    def test_update_user(self):
        u = self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        updated = self.svc.update_user(u.scim_id, display_name="John Doe")
        assert updated.display_name == "John Doe"

    def test_deactivate_user(self):
        u = self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        self.svc.deactivate_user(u.scim_id)
        assert not u.active

    def test_delete_user(self):
        u = self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        assert self.svc.delete_user(u.scim_id)
        assert self.svc.get_user(u.scim_id) is None

    def test_list_users(self):
        self.svc.create_user("t1", "ext-1", "jdoe", "jdoe@example.com")
        self.svc.create_user("t1", "ext-2", "jsmith", "js@example.com")
        result = self.svc.list_users("t1")
        assert result["total_results"] == 2
