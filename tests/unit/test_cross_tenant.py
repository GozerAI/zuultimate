"""Tests for cross-tenant collaboration (424)."""
from zuultimate.enterprise.cross_tenant import CrossTenantService

class TestCrossTenant:
    def setup_method(self):
        self.svc = CrossTenantService()

    def test_create_rule(self):
        r = self.svc.create_rule("t1", "t2", resources=["docs"], actions=["read"])
        assert r.rule_id.startswith("collab-")

    def test_check_access_allowed(self):
        self.svc.create_rule("t1", "t2", resources=["docs"], actions=["read"])
        assert self.svc.check_access("t1", "t2", "docs", "read")

    def test_check_access_denied(self):
        self.svc.create_rule("t1", "t2", resources=["docs"], actions=["read"])
        assert not self.svc.check_access("t1", "t2", "docs", "write")

    def test_wildcard_access(self):
        self.svc.create_rule("t1", "t2", resources=["*"], actions=["*"])
        assert self.svc.check_access("t1", "t2", "anything", "anything")

    def test_revoke_rule(self):
        r = self.svc.create_rule("t1", "t2", resources=["docs"], actions=["read"])
        self.svc.revoke_rule(r.rule_id)
        assert not self.svc.check_access("t1", "t2", "docs", "read")

    def test_get_rules(self):
        self.svc.create_rule("t1", "t2", resources=["docs"])
        assert len(self.svc.get_rules("t1")) == 1
