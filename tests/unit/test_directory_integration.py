"""Tests for directory integration (420)."""
from zuultimate.enterprise.directory_integration import DirectoryIntegrationService

class TestDirectoryIntegration:
    def setup_method(self):
        self.svc = DirectoryIntegrationService()

    def test_register_directory(self):
        c = self.svc.register_directory("t1", "azure_ad", "https://graph.microsoft.com")
        assert c.provider == "azure_ad"

    def test_get_configs(self):
        self.svc.register_directory("t1", "azure_ad")
        self.svc.register_directory("t1", "okta")
        configs = self.svc.get_configs_for_tenant("t1")
        assert len(configs) == 2

    def test_sync_directory(self):
        c = self.svc.register_directory("t1", "azure_ad")
        result = self.svc.sync_directory(c.config_id, users_count=50, groups_count=5)
        assert result["synced_users"] == 50

    def test_deactivate(self):
        c = self.svc.register_directory("t1", "azure_ad")
        self.svc.deactivate(c.config_id)
        assert not c.is_active
