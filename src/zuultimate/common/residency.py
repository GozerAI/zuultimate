"""Data residency enforcement for sovereign data protection."""

import enum
import json

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.residency")


class ReplicationPolicy(enum.Enum):
    CONTROL_PLANE_GLOBAL = "global"
    SOVEREIGN_RING_ONLY = "sovereign"


# Tables containing PII that must stay in the sovereignty ring
SOVEREIGN_TABLES = {"users", "credentials", "user_sessions", "auth_events", "mfa_devices"}

# Tables that can replicate globally (config, policies, roles)
GLOBAL_TABLES = {"tenants", "roles", "policies", "api_keys"}


def get_replication_policy(table_name: str) -> ReplicationPolicy:
    """Return the replication policy for a given table."""
    if table_name in SOVEREIGN_TABLES:
        return ReplicationPolicy.SOVEREIGN_RING_ONLY
    return ReplicationPolicy.CONTROL_PLANE_GLOBAL


class ResidencyViolationError(Exception):
    """Raised when a data residency constraint would be violated."""


class ResidencyViolationGuard:
    """Validates data residency constraints before DB writes.

    Usage::

        guard = ResidencyViolationGuard(current_region="eu", current_ring="eu")
        if not guard.check_write_allowed("users", tenant.sovereignty_ring):
            raise ResidencyViolationError("Write not permitted in this region")
    """

    def __init__(self, current_region: str, current_ring: str) -> None:
        self.current_region = current_region
        self.current_ring = current_ring

    def check_write_allowed(
        self,
        table_name: str,
        tenant_sovereignty_ring: str | None,
    ) -> bool:
        """Return True if a write to *table_name* is allowed in this region/ring.

        Rules:
        - GLOBAL tables are always allowed.
        - SOVEREIGN tables require that the tenant's sovereignty ring matches
          this node's ring, or that the tenant uses the ``"global"`` ring
          (meaning no restriction is placed).
        - A ``None`` sovereignty ring is treated as unrestricted (legacy records).
        """
        policy = get_replication_policy(table_name)
        if policy == ReplicationPolicy.CONTROL_PLANE_GLOBAL:
            return True
        if tenant_sovereignty_ring is None:
            return True
        if tenant_sovereignty_ring == "global":
            return True
        if tenant_sovereignty_ring == self.current_ring:
            return True
        _log.warning(
            "Residency violation: table=%s tenant_ring=%s current_ring=%s",
            table_name,
            tenant_sovereignty_ring,
            self.current_ring,
        )
        return False

    def validate_pii_region(
        self,
        tenant_pii_regions_json: str,
        target_region: str,
    ) -> bool:
        """Return True if *target_region* is in the tenant's allowed PII regions list.

        Falls back to [current_ring] if the JSON is malformed or absent.
        """
        try:
            allowed: list[str] = json.loads(tenant_pii_regions_json)
        except (json.JSONDecodeError, TypeError):
            allowed = [self.current_ring]
        return target_region in allowed
