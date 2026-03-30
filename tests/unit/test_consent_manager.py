"""Unit tests for automated consent management (item 905)."""

import pytest
from datetime import datetime, timedelta, timezone

from zuultimate.compliance.consent_manager import (
    ConsentEntry,
    ConsentManager,
    ConsentPurpose,
    ConsentStatus,
)


class TestConsentManager:
    @pytest.fixture
    def mgr(self):
        return ConsentManager(default_expiry_days=365)

    def test_grant_consent(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        assert entry.status == ConsentStatus.GRANTED
        assert entry.purpose == ConsentPurpose.MARKETING
        assert entry.is_active

    def test_has_consent(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.ANALYTICS)
        assert mgr.has_consent("t1", "u1", ConsentPurpose.ANALYTICS)
        assert not mgr.has_consent("t1", "u1", ConsentPurpose.MARKETING)

    def test_revoke_consent(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        result = mgr.revoke("t1", "u1", ConsentPurpose.MARKETING)
        assert result is not None
        assert result.status == ConsentStatus.REVOKED
        assert not mgr.has_consent("t1", "u1", ConsentPurpose.MARKETING)

    def test_revoke_nonexistent(self, mgr):
        assert mgr.revoke("t1", "u1", ConsentPurpose.MARKETING) is None

    def test_revoke_already_revoked(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        mgr.revoke("t1", "u1", ConsentPurpose.MARKETING)
        assert mgr.revoke("t1", "u1", ConsentPurpose.MARKETING) is None

    def test_get_consent(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.ESSENTIAL)
        entry = mgr.get_consent("t1", "u1", ConsentPurpose.ESSENTIAL)
        assert entry is not None
        assert entry.purpose == ConsentPurpose.ESSENTIAL

    def test_get_all_consents(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        mgr.grant("t1", "u1", ConsentPurpose.ANALYTICS)
        mgr.grant("t1", "u2", ConsentPurpose.MARKETING)
        all_u1 = mgr.get_all_consents("t1", "u1")
        assert len(all_u1) == 2

    def test_get_active_consents(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        mgr.grant("t1", "u1", ConsentPurpose.ANALYTICS)
        mgr.revoke("t1", "u1", ConsentPurpose.MARKETING)
        active = mgr.get_active_consents("t1", "u1")
        assert len(active) == 1
        assert active[0].purpose == ConsentPurpose.ANALYTICS

    def test_revoke_all(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        mgr.grant("t1", "u1", ConsentPurpose.ANALYTICS)
        mgr.grant("t1", "u1", ConsentPurpose.THIRD_PARTY)
        count = mgr.revoke_all("t1", "u1")
        assert count == 3
        assert len(mgr.get_active_consents("t1", "u1")) == 0

    def test_expire_stale(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING, expiry_days=0)
        # Manually set expires_at to past
        entry.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        expired = mgr.expire_stale()
        assert len(expired) == 1
        assert expired[0].status == ConsentStatus.EXPIRED

    def test_consent_expiry_check(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        entry.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert entry.is_expired
        assert not entry.is_active

    def test_custom_expiry(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING, expiry_days=30)
        assert entry.expires_at is not None
        delta = entry.expires_at - entry.granted_at
        assert 29 <= delta.days <= 30

    def test_consent_version_and_channel(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING,
                          version="2.0", channel="web")
        assert entry.version == "2.0"
        assert entry.channel == "web"

    def test_compliance_summary(self, mgr):
        mgr.grant("t1", "u1", ConsentPurpose.MARKETING)
        mgr.grant("t1", "u1", ConsentPurpose.ANALYTICS)
        mgr.grant("t1", "u2", ConsentPurpose.MARKETING)
        mgr.revoke("t1", "u1", ConsentPurpose.MARKETING)
        summary = mgr.get_compliance_summary("t1")
        assert summary["tenant_id"] == "t1"
        assert summary["total_records"] == 3
        assert summary["active_consents"] == 2
        assert summary["revoked"] == 1

    def test_metadata(self, mgr):
        entry = mgr.grant("t1", "u1", ConsentPurpose.MARKETING,
                          metadata={"source": "onboarding"})
        assert entry.metadata == {"source": "onboarding"}
