"""ZuulLicenseGate — feature entitlement checker for zuultimate.

Same enforcement philosophy as ag3ntwerk LicenseGate:
- No VINZY_LICENSE_KEY → community only (gated features blocked)
- Key + entitled → allow
- Key + NOT entitled → block
- Server unreachable → community only (fail-closed for gated features)
"""

import functools
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

PRICING_URL = "https://1450enterprises.com/pricing"

_FEATURE_TIER_MAP = {
    # Pro (Tier 2)
    "zul.rbac.matrix": ("Executive RBAC Matrix", "Pro"),
    "zul.compliance.reporter": ("Compliance Reporting", "Pro"),
    "zul.sso.oidc": ("SSO / OIDC", "Pro"),
    # Enterprise (Tier 1)
    "zul.gateway.middleware": ("AI Security Gateway", "Enterprise"),
    "zul.gateway.standalone": ("Gateway Standalone App", "Enterprise"),
    "zul.toolguard.pipeline": ("ToolGuard Pipeline", "Enterprise"),
    "zul.injection.patterns": ("Injection Pattern Library", "Enterprise"),
    "zul.redteam.tool": ("Red Team Tool", "Enterprise"),
}


class ZuulLicenseGate:
    """Cached feature entitlement checker backed by Vinzy-Engine SDK."""

    def __init__(
        self,
        license_key: Optional[str] = None,
        server_url: Optional[str] = None,
        cache_ttl: int = 300,
    ):
        self._license_key = license_key or os.environ.get("VINZY_LICENSE_KEY", "")
        self._server_url = server_url or os.environ.get(
            "VINZY_SERVER", "http://localhost:8080"
        )
        self._cache_ttl = cache_ttl
        self._client = None
        self._features_cache: Optional[list[str]] = None
        self._cache_time: float = 0.0

    @property
    def is_community_mode(self) -> bool:
        return not self._license_key

    def _get_client(self):
        if self._client is None:
            try:
                from vinzy_engine import LicenseClient

                self._client = LicenseClient(
                    server_url=self._server_url,
                    license_key=self._license_key,
                    cache_ttl=self._cache_ttl,
                )
            except ImportError:
                logger.debug("vinzy_engine not installed; ZuulLicenseGate in community mode")
                return None
        return self._client

    def _refresh_features(self) -> list[str]:
        now = time.time()
        if self._features_cache is not None and (now - self._cache_time) < self._cache_ttl:
            return self._features_cache

        client = self._get_client()
        if client is None:
            return []

        try:
            result = client.validate()
            if result.valid:
                self._features_cache = result.features
                self._cache_time = now
                return self._features_cache
            self._features_cache = []
            self._cache_time = now
            return []
        except Exception:
            logger.debug("Vinzy-Engine unreachable; fail-closed", exc_info=True)
            return []

    def check_feature(self, flag: str) -> bool:
        if self.is_community_mode:
            return False
        features = self._refresh_features()
        if not features:
            return False
        return flag in features

    def require_feature(self, flag: str, label: str | None = None):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self.check_feature(flag):
                    name, tier = _FEATURE_TIER_MAP.get(flag, (flag, "a commercial"))
                    raise PermissionError(
                        f"{label or name} requires {tier} license. "
                        f"Set VINZY_LICENSE_KEY or visit {PRICING_URL}"
                    )
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def gate(self, flag: str, label: str | None = None) -> None:
        if not self.check_feature(flag):
            name, tier = _FEATURE_TIER_MAP.get(flag, (flag, "a commercial"))
            raise PermissionError(
                f"{label or name} requires {tier} license. "
                f"Set VINZY_LICENSE_KEY or visit {PRICING_URL}"
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


license_gate = ZuulLicenseGate()
