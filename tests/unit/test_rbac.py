"""Tests for custom RBAC (398)."""
from zuultimate.enterprise.rbac import RBACService

class TestRBAC:
    def setup_method(self):
        self.svc = RBACService()

    def test_create_role(self):
        r = self.svc.create_role("t1", "editor", permissions=["docs:read", "docs:write"])
        assert r.role_id.startswith("role-")

    def test_list_roles_includes_system(self):
        roles = self.svc.list_roles("t1")
        names = [r.name for r in roles]
        assert "Admin" in names

    def test_assign_and_check_permission(self):
        r = self.svc.create_role("t1", "editor", permissions=["docs:read", "docs:write"])
        self.svc.assign_role("u1", r.role_id, "t1")
        assert self.svc.check_permission("u1", "t1", "docs", "read")
        assert not self.svc.check_permission("u1", "t1", "vault", "write")

    def test_admin_has_all_access(self):
        self.svc.assign_role("u1", "sys-admin", "t1")
        assert self.svc.check_permission("u1", "t1", "anything", "anything")

    def test_revoke_role(self):
        r = self.svc.create_role("t1", "editor", permissions=["docs:read"])
        self.svc.assign_role("u1", r.role_id, "t1")
        self.svc.revoke_role("u1", r.role_id, "t1")
        assert not self.svc.check_permission("u1", "t1", "docs", "read")

    def test_delete_role(self):
        r = self.svc.create_role("t1", "editor")
        assert self.svc.delete_role(r.role_id)
        assert self.svc.get_role(r.role_id) is None

    def test_cannot_delete_system_role(self):
        assert not self.svc.delete_role("sys-admin")
