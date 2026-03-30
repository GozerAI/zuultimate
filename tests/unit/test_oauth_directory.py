"""Tests for OAuth app directory (434)."""
from zuultimate.enterprise.oauth_directory import OAuthDirectoryService

class TestOAuthDirectory:
    def setup_method(self):
        self.svc = OAuthDirectoryService()

    def test_register_app(self):
        app = self.svc.register_app("TestApp", "client-123")
        assert app.app_id.startswith("oauth-")
        assert not app.is_approved

    def test_approve_app(self):
        app = self.svc.register_app("TestApp", "client-123")
        self.svc.approve_app(app.app_id)
        assert app.is_approved

    def test_install_unapproved_fails(self):
        app = self.svc.register_app("TestApp", "client-123")
        assert self.svc.install_app(app.app_id, "t1") is None

    def test_install_approved(self):
        app = self.svc.register_app("TestApp", "client-123")
        self.svc.approve_app(app.app_id)
        inst = self.svc.install_app(app.app_id, "t1")
        assert inst is not None

    def test_uninstall_app(self):
        app = self.svc.register_app("TestApp", "client-123")
        self.svc.approve_app(app.app_id)
        self.svc.install_app(app.app_id, "t1")
        self.svc.uninstall_app(app.app_id, "t1")
        assert len(self.svc.get_installed_apps("t1")) == 0

    def test_list_apps(self):
        a1 = self.svc.register_app("App1", "c1")
        a2 = self.svc.register_app("App2", "c2")
        self.svc.approve_app(a1.app_id)
        assert len(self.svc.list_apps(approved_only=True)) == 1
        assert len(self.svc.list_apps(approved_only=False)) == 2
