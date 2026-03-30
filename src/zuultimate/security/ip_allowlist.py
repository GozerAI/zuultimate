"""IP allowlisting per tenant.

Manages per-tenant IP allowlists for restricting API access to known
IP addresses and CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class IPAllowlistEntry:
    """An IP address or CIDR range in a tenant allowlist."""
    entry_id: str
    tenant_id: str
    cidr: str  # single IP or CIDR notation
    label: str = ""
    created_at: float = field(default_factory=time.time)
    created_by: str = ""
    expires_at: float | None = None
    enabled: bool = True

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr in self.network
        except ValueError:
            return False


class IPAllowlistManager:
    """Manages IP allowlists per tenant.

    Usage::

        manager = IPAllowlistManager()
        manager.add("tenant-1", "192.168.1.0/24", label="Office")
        assert manager.is_allowed("tenant-1", "192.168.1.50")
        assert not manager.is_allowed("tenant-1", "10.0.0.1")
    """

    def __init__(self, default_allow: bool = False) -> None:
        self._entries: dict[str, list[IPAllowlistEntry]] = {}
        self._counter = 0
        self.default_allow = default_allow

    def add(
        self,
        tenant_id: str,
        cidr: str,
        label: str = "",
        created_by: str = "",
        expires_at: float | None = None,
    ) -> IPAllowlistEntry:
        # Validate CIDR
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {cidr}") from exc

        self._counter += 1
        entry = IPAllowlistEntry(
            entry_id=f"ip-{self._counter}",
            tenant_id=tenant_id, cidr=cidr, label=label,
            created_by=created_by, expires_at=expires_at,
        )
        if tenant_id not in self._entries:
            self._entries[tenant_id] = []
        self._entries[tenant_id].append(entry)
        return entry

    def remove(self, tenant_id: str, entry_id: str) -> bool:
        entries = self._entries.get(tenant_id, [])
        before = len(entries)
        self._entries[tenant_id] = [e for e in entries if e.entry_id != entry_id]
        return len(self._entries[tenant_id]) < before

    def is_allowed(self, tenant_id: str, ip: str) -> bool:
        """Check if an IP is allowed for a tenant."""
        entries = self._entries.get(tenant_id)
        if entries is None:
            return self.default_allow  # no allowlist = use default

        active_entries = [e for e in entries if e.enabled and not e.is_expired]
        if not active_entries:
            return self.default_allow

        return any(e.contains(ip) for e in active_entries)

    def get_entries(self, tenant_id: str) -> list[IPAllowlistEntry]:
        return list(self._entries.get(tenant_id, []))

    def get_active_entries(self, tenant_id: str) -> list[IPAllowlistEntry]:
        return [e for e in self.get_entries(tenant_id) if e.enabled and not e.is_expired]

    def disable_entry(self, tenant_id: str, entry_id: str) -> bool:
        for entry in self._entries.get(tenant_id, []):
            if entry.entry_id == entry_id:
                entry.enabled = False
                return True
        return False

    def enable_entry(self, tenant_id: str, entry_id: str) -> bool:
        for entry in self._entries.get(tenant_id, []):
            if entry.entry_id == entry_id:
                entry.enabled = True
                return True
        return False

    def clear_tenant(self, tenant_id: str) -> int:
        entries = self._entries.pop(tenant_id, [])
        return len(entries)

    def cleanup_expired(self) -> int:
        count = 0
        for tenant_id in list(self._entries.keys()):
            before = len(self._entries[tenant_id])
            self._entries[tenant_id] = [e for e in self._entries[tenant_id] if not e.is_expired]
            count += before - len(self._entries[tenant_id])
        return count

    def get_summary(self, tenant_id: str | None = None) -> dict[str, Any]:
        if tenant_id:
            entries = self.get_entries(tenant_id)
            return {
                "tenant_id": tenant_id,
                "total_entries": len(entries),
                "active_entries": len([e for e in entries if e.enabled and not e.is_expired]),
                "disabled_entries": len([e for e in entries if not e.enabled]),
                "expired_entries": len([e for e in entries if e.is_expired]),
            }
        total = sum(len(v) for v in self._entries.values())
        return {
            "total_tenants": len(self._entries),
            "total_entries": total,
        }
