"""Tests for delegated admin (412)."""
from zuultimate.enterprise.delegated_admin import DelegatedAdminService

class TestDelegatedAdmin:
    def setup_method(self):
        self.svc = DelegatedAdminService()

    def test_grant_admin(self):
        a = self.svc.grant_admin("t1", "u1", scope=["users:read", "users:write"])
        assert a.is_active

    def test_check_admin(self):
        self.svc.grant_admin("t1", "u1", scope=["users:read"])
        assert self.svc.check_admin("t1", "u1", "users:read")
        assert not self.svc.check_admin("t1", "u1", "users:delete")

    def test_revoke_admin(self):
        a = self.svc.grant_admin("t1", "u1")
        self.svc.revoke_admin(a.admin_id)
        assert not self.svc.check_admin("t1", "u1", "users:read")

    def test_get_admins(self):
        self.svc.grant_admin("t1", "u1")
        self.svc.grant_admin("t1", "u2")
        assert len(self.svc.get_admins("t1")) == 2

    def test_get_scopes(self):
        self.svc.grant_admin("t1", "u1", scope=["users:read", "billing:read"])
        scopes = self.svc.get_admin_scopes("t1", "u1")
        assert "users:read" in scopes
        assert "billing:read" in scopes
