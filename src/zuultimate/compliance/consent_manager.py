"""Automated consent management.

High-level consent orchestration that wraps per-purpose consent tracking,
bulk operations, compliance checks, and consent expiry enforcement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ConsentStatus(str, Enum):
    GRANTED = "granted"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class ConsentPurpose(str, Enum):
    ESSENTIAL = "essential"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    THIRD_PARTY = "third_party"
    PROFILING = "profiling"
    DATA_SHARING = "data_sharing"


@dataclass
class ConsentEntry:
    consent_id: str
    tenant_id: str
    subject_id: str
    purpose: ConsentPurpose
    status: ConsentStatus
    granted_at: datetime | None = None
    revoked_at: datetime | None = None
    expires_at: datetime | None = None
    version: str = "1.0"
    channel: str = "api"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        if self.status != ConsentStatus.GRANTED:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class ConsentManager:
    """Manages consent lifecycle for data subjects.

    Usage::

        manager = ConsentManager()
        manager.grant("t1", "user-1", ConsentPurpose.MARKETING)
        assert manager.has_consent("t1", "user-1", ConsentPurpose.MARKETING)
        manager.revoke("t1", "user-1", ConsentPurpose.MARKETING)
    """

    def __init__(self, default_expiry_days: int = 365) -> None:
        self._store: dict[str, ConsentEntry] = {}  # keyed by composite key
        self._counter = 0
        self.default_expiry_days = default_expiry_days

    def _key(self, tenant_id: str, subject_id: str, purpose: ConsentPurpose) -> str:
        return f"{tenant_id}:{subject_id}:{purpose.value}"

    def grant(
        self,
        tenant_id: str,
        subject_id: str,
        purpose: ConsentPurpose,
        version: str = "1.0",
        channel: str = "api",
        expiry_days: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ConsentEntry:
        self._counter += 1
        now = datetime.now(timezone.utc)
        days = expiry_days if expiry_days is not None else self.default_expiry_days
        entry = ConsentEntry(
            consent_id=f"consent-{self._counter}",
            tenant_id=tenant_id, subject_id=subject_id,
            purpose=purpose, status=ConsentStatus.GRANTED,
            granted_at=now, expires_at=now + timedelta(days=days),
            version=version, channel=channel,
            metadata=metadata or {},
        )
        self._store[self._key(tenant_id, subject_id, purpose)] = entry
        return entry

    def revoke(self, tenant_id: str, subject_id: str, purpose: ConsentPurpose) -> ConsentEntry | None:
        key = self._key(tenant_id, subject_id, purpose)
        entry = self._store.get(key)
        if entry is None or entry.status != ConsentStatus.GRANTED:
            return None
        entry.status = ConsentStatus.REVOKED
        entry.revoked_at = datetime.now(timezone.utc)
        return entry

    def has_consent(self, tenant_id: str, subject_id: str, purpose: ConsentPurpose) -> bool:
        key = self._key(tenant_id, subject_id, purpose)
        entry = self._store.get(key)
        return entry is not None and entry.is_active

    def get_consent(self, tenant_id: str, subject_id: str, purpose: ConsentPurpose) -> ConsentEntry | None:
        return self._store.get(self._key(tenant_id, subject_id, purpose))

    def get_all_consents(self, tenant_id: str, subject_id: str) -> list[ConsentEntry]:
        prefix = f"{tenant_id}:{subject_id}:"
        return [e for k, e in self._store.items() if k.startswith(prefix)]

    def get_active_consents(self, tenant_id: str, subject_id: str) -> list[ConsentEntry]:
        return [e for e in self.get_all_consents(tenant_id, subject_id) if e.is_active]

    def revoke_all(self, tenant_id: str, subject_id: str) -> int:
        """Revoke all active consents for a subject. Returns count of revoked."""
        count = 0
        for entry in self.get_active_consents(tenant_id, subject_id):
            self.revoke(tenant_id, subject_id, entry.purpose)
            count += 1
        return count

    def expire_stale(self) -> list[ConsentEntry]:
        """Find and mark all expired consents. Returns list of newly expired entries."""
        expired: list[ConsentEntry] = []
        for entry in self._store.values():
            if entry.status == ConsentStatus.GRANTED and entry.is_expired:
                entry.status = ConsentStatus.EXPIRED
                expired.append(entry)
        return expired

    def get_compliance_summary(self, tenant_id: str) -> dict[str, Any]:
        entries = [e for e in self._store.values() if e.tenant_id == tenant_id]
        active = [e for e in entries if e.is_active]
        by_purpose: dict[str, int] = {}
        for e in active:
            by_purpose[e.purpose.value] = by_purpose.get(e.purpose.value, 0) + 1
        return {
            "tenant_id": tenant_id,
            "total_records": len(entries),
            "active_consents": len(active),
            "revoked": sum(1 for e in entries if e.status == ConsentStatus.REVOKED),
            "expired": sum(1 for e in entries if e.status == ConsentStatus.EXPIRED),
            "by_purpose": by_purpose,
        }
