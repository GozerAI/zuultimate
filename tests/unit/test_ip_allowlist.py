"""Unit tests for IP allowlisting per tenant (security module)."""

import time
import pytest

from zuultimate.security.ip_allowlist import (
    IPAllowlistEntry,
    IPAllowlistManager,
)


class TestIPAllowlistManager:
    @pytest.fixture
    def mgr(self):
        return IPAllowlistManager(default_allow=False)

    def test_no_allowlist_uses_default(self, mgr):
        assert not mgr.is_allowed("t1", "1.2.3.4")

    def test_no_allowlist_default_allow(self):
        mgr = IPAllowlistManager(default_allow=True)
        assert mgr.is_allowed("t1", "1.2.3.4")

    def test_add_and_check_single_ip(self, mgr):
        mgr.add("t1", "1.2.3.4/32", label="Server")
        assert mgr.is_allowed("t1", "1.2.3.4")
        assert not mgr.is_allowed("t1", "1.2.3.5")

    def test_add_and_check_cidr(self, mgr):
        mgr.add("t1", "192.168.1.0/24", label="Office")
        assert mgr.is_allowed("t1", "192.168.1.50")
        assert mgr.is_allowed("t1", "192.168.1.255")
        assert not mgr.is_allowed("t1", "192.168.2.1")

    def test_invalid_cidr_raises(self, mgr):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            mgr.add("t1", "not-a-cidr")

    def test_remove_entry(self, mgr):
        entry = mgr.add("t1", "1.2.3.4/32")
        assert mgr.remove("t1", entry.entry_id)
        assert not mgr.is_allowed("t1", "1.2.3.4")

    def test_disable_enable_entry(self, mgr):
        entry = mgr.add("t1", "1.2.3.4/32")
        mgr.disable_entry("t1", entry.entry_id)
        assert not mgr.is_allowed("t1", "1.2.3.4")
        mgr.enable_entry("t1", entry.entry_id)
        assert mgr.is_allowed("t1", "1.2.3.4")

    def test_expired_entry_ignored(self, mgr):
        entry = mgr.add("t1", "1.2.3.4/32", expires_at=time.time() - 100)
        assert not mgr.is_allowed("t1", "1.2.3.4")

    def test_get_entries(self, mgr):
        mgr.add("t1", "1.2.3.0/24")
        mgr.add("t1", "10.0.0.0/8")
        assert len(mgr.get_entries("t1")) == 2

    def test_get_active_entries(self, mgr):
        mgr.add("t1", "1.2.3.0/24")
        e2 = mgr.add("t1", "10.0.0.0/8")
        mgr.disable_entry("t1", e2.entry_id)
        assert len(mgr.get_active_entries("t1")) == 1

    def test_clear_tenant(self, mgr):
        mgr.add("t1", "1.2.3.0/24")
        mgr.add("t1", "10.0.0.0/8")
        count = mgr.clear_tenant("t1")
        assert count == 2
        assert len(mgr.get_entries("t1")) == 0

    def test_cleanup_expired(self, mgr):
        mgr.add("t1", "1.2.3.0/24")
        mgr.add("t1", "10.0.0.0/8", expires_at=time.time() - 100)
        count = mgr.cleanup_expired()
        assert count == 1
        assert len(mgr.get_entries("t1")) == 1

    def test_tenant_isolation(self, mgr):
        mgr.add("t1", "1.2.3.0/24")
        assert mgr.is_allowed("t1", "1.2.3.1")
        assert not mgr.is_allowed("t2", "1.2.3.1")

    def test_get_summary_per_tenant(self, mgr):
        mgr.add("t1", "1.0.0.0/8")
        e2 = mgr.add("t1", "2.0.0.0/8")
        mgr.disable_entry("t1", e2.entry_id)
        s = mgr.get_summary("t1")
        assert s["total_entries"] == 2
        assert s["active_entries"] == 1
        assert s["disabled_entries"] == 1

    def test_get_summary_global(self, mgr):
        mgr.add("t1", "1.0.0.0/8")
        mgr.add("t2", "2.0.0.0/8")
        s = mgr.get_summary()
        assert s["total_tenants"] == 2
        assert s["total_entries"] == 2

    def test_entry_contains(self):
        entry = IPAllowlistEntry(
            entry_id="e1", tenant_id="t1", cidr="10.0.0.0/8",
        )
        assert entry.contains("10.1.2.3")
        assert not entry.contains("192.168.1.1")
        assert not entry.contains("not-an-ip")
