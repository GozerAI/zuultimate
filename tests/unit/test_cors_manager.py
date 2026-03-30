"""Unit tests for CORS configuration auto-management (item 931)."""

import pytest

from zuultimate.compliance.cors_manager import (
    CORSConfig,
    CORSManager,
    CORSProfile,
    CORSRule,
)


class TestCORSManager:
    @pytest.fixture
    def manager(self):
        return CORSManager(profile=CORSProfile.STANDARD)

    def test_no_origins_denies_all(self, manager):
        config = manager.check_origin("https://evil.com")
        assert not config.allowed

    def test_add_and_check_origin(self, manager):
        manager.add_origin("https://app.example.com")
        config = manager.check_origin("https://app.example.com")
        assert config.allowed
        assert config.origin == "https://app.example.com"

    def test_unregistered_origin_denied(self, manager):
        manager.add_origin("https://app.example.com")
        config = manager.check_origin("https://other.com")
        assert not config.allowed

    def test_pattern_matching(self, manager):
        manager.add_pattern(r"https://.*\.example\.com")
        assert manager.check_origin("https://app.example.com").allowed
        assert manager.check_origin("https://api.example.com").allowed
        assert not manager.check_origin("https://evil.com").allowed

    def test_block_origin(self, manager):
        manager.add_origin("https://app.example.com")
        manager.block_origin("https://app.example.com")
        assert not manager.check_origin("https://app.example.com").allowed

    def test_unblock_origin(self, manager):
        manager.add_origin("https://app.example.com")
        manager.block_origin("https://app.example.com")
        manager.unblock_origin("https://app.example.com")
        assert manager.check_origin("https://app.example.com").allowed

    def test_remove_origin(self, manager):
        manager.add_origin("https://app.example.com")
        assert manager.remove_origin("https://app.example.com")
        assert not manager.check_origin("https://app.example.com").allowed
        assert not manager.remove_origin("nonexistent")

    def test_allowed_origins_list(self, manager):
        manager.add_origin("https://a.com")
        manager.add_origin("https://b.com")
        assert set(manager.allowed_origins) == {"https://a.com", "https://b.com"}

    def test_strict_profile(self):
        manager = CORSManager(profile=CORSProfile.STRICT)
        manager.add_origin("https://a.com")
        config = manager.check_origin("https://a.com")
        assert config.allowed
        assert "DELETE" not in config.allow_methods
        assert config.max_age == 600

    def test_permissive_profile(self):
        manager = CORSManager(profile=CORSProfile.PERMISSIVE)
        manager.add_origin("https://a.com")
        config = manager.check_origin("https://a.com")
        assert config.allowed
        assert not config.allow_credentials
        assert config.max_age == 86400

    def test_standard_profile_methods(self, manager):
        manager.add_origin("https://a.com")
        config = manager.check_origin("https://a.com")
        assert "GET" in config.allow_methods
        assert "POST" in config.allow_methods
        assert "DELETE" in config.allow_methods

    def test_get_summary(self, manager):
        manager.add_origin("https://a.com")
        manager.block_origin("https://bad.com")
        s = manager.get_summary()
        assert s["profile"] == "standard"
        assert s["allowed_origin_count"] == 1
        assert s["blocked_origin_count"] == 1

    def test_invalid_regex_pattern_skipped(self, manager):
        manager.add_pattern("[invalid-regex")
        config = manager.check_origin("anything")
        assert not config.allowed

    def test_origin_overrides(self, manager):
        manager.add_origin("https://a.com", max_age=7200)
        config = manager.check_origin("https://a.com")
        assert config.max_age == 7200
