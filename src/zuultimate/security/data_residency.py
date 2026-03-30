"""Data residency controls.

Enforces data residency requirements per tenant, ensuring data stays in
the designated geographic region and meets sovereignty requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Region(str, Enum):
    US = "us"
    EU = "eu"
    UK = "uk"
    CA = "ca"
    AU = "au"
    JP = "jp"
    GLOBAL = "global"


class ResidencyRequirement(str, Enum):
    STRICT = "strict"       # data must stay in assigned region
    PREFERRED = "preferred"  # data should stay but can overflow
    NONE = "none"           # no residency requirement


@dataclass
class TenantResidencyConfig:
    tenant_id: str
    home_region: Region
    requirement: ResidencyRequirement = ResidencyRequirement.STRICT
    allowed_regions: list[Region] = field(default_factory=list)
    pii_region: Region | None = None  # if different from home
    backup_region: Region | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.allowed_regions:
            self.allowed_regions = [self.home_region]
        if self.pii_region is None:
            self.pii_region = self.home_region

    def is_region_allowed(self, region: Region) -> bool:
        if self.requirement == ResidencyRequirement.NONE:
            return True
        if region == Region.GLOBAL:
            return self.requirement != ResidencyRequirement.STRICT
        return region in self.allowed_regions

    def is_pii_region_allowed(self, region: Region) -> bool:
        """PII is always strict -- must be in pii_region or home_region."""
        return region in (self.pii_region, self.home_region)


@dataclass
class ResidencyViolation:
    tenant_id: str
    operation: str
    target_region: Region
    required_region: Region
    data_type: str
    message: str


class DataResidencyController:
    """Enforces data residency controls per tenant.

    Usage::

        controller = DataResidencyController(current_region=Region.US)
        controller.register_tenant(TenantResidencyConfig(
            tenant_id="t1", home_region=Region.EU,
            requirement=ResidencyRequirement.STRICT,
        ))
        violation = controller.check_write("t1", "users")
        assert violation is not None  # writing EU data in US region
    """

    def __init__(self, current_region: Region = Region.US) -> None:
        self.current_region = current_region
        self._configs: dict[str, TenantResidencyConfig] = {}

    def register_tenant(self, config: TenantResidencyConfig) -> None:
        self._configs[config.tenant_id] = config

    def unregister_tenant(self, tenant_id: str) -> bool:
        return self._configs.pop(tenant_id, None) is not None

    def get_config(self, tenant_id: str) -> TenantResidencyConfig | None:
        return self._configs.get(tenant_id)

    def check_write(self, tenant_id: str, data_type: str) -> ResidencyViolation | None:
        """Check if a write operation is allowed in the current region."""
        config = self._configs.get(tenant_id)
        if config is None:
            return None  # no config = no restriction

        is_pii = data_type in ("users", "credentials", "user_sessions", "auth_events", "mfa_devices")

        if is_pii:
            if not config.is_pii_region_allowed(self.current_region):
                return ResidencyViolation(
                    tenant_id=tenant_id, operation="write",
                    target_region=self.current_region,
                    required_region=config.pii_region or config.home_region,
                    data_type=data_type,
                    message=f"PII data for {tenant_id} must reside in "
                            f"{config.pii_region or config.home_region}, "
                            f"current region is {self.current_region}",
                )
        else:
            if not config.is_region_allowed(self.current_region):
                return ResidencyViolation(
                    tenant_id=tenant_id, operation="write",
                    target_region=self.current_region,
                    required_region=config.home_region,
                    data_type=data_type,
                    message=f"Data for {tenant_id} must reside in "
                            f"{config.home_region}, current region is {self.current_region}",
                )

        return None

    def check_read(self, tenant_id: str, data_type: str) -> ResidencyViolation | None:
        """Check if a read operation is allowed (reads are less restrictive)."""
        config = self._configs.get(tenant_id)
        if config is None:
            return None
        # Only strict PII data has read restrictions
        if config.requirement != ResidencyRequirement.STRICT:
            return None
        is_pii = data_type in ("users", "credentials", "user_sessions", "auth_events", "mfa_devices")
        if is_pii and not config.is_pii_region_allowed(self.current_region):
            return ResidencyViolation(
                tenant_id=tenant_id, operation="read",
                target_region=self.current_region,
                required_region=config.pii_region or config.home_region,
                data_type=data_type,
                message=f"PII reads for {tenant_id} restricted to {config.pii_region}",
            )
        return None

    def get_violations_summary(self) -> dict[str, Any]:
        return {
            "current_region": self.current_region.value,
            "registered_tenants": len(self._configs),
            "strict_tenants": sum(
                1 for c in self._configs.values()
                if c.requirement == ResidencyRequirement.STRICT
            ),
            "tenants_in_region": sum(
                1 for c in self._configs.values()
                if c.home_region == self.current_region
            ),
        }
