"""CORS configuration auto-management.

Dynamically manages CORS allowed origins based on tenant configurations,
environment, and security policies.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CORSProfile(str, Enum):
    STRICT = "strict"
    STANDARD = "standard"
    PERMISSIVE = "permissive"


@dataclass
class CORSRule:
    """A CORS configuration rule for a tenant or environment."""
    origin_pattern: str  # exact origin or regex pattern
    allow_credentials: bool = True
    allow_methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    allow_headers: list[str] = field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-ID"])
    max_age: int = 3600
    expose_headers: list[str] = field(default_factory=list)


@dataclass
class CORSConfig:
    """Resolved CORS configuration for a request."""
    allowed: bool
    origin: str
    allow_credentials: bool = True
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    max_age: int = 3600
    expose_headers: list[str] = field(default_factory=list)


_PROFILE_DEFAULTS: dict[CORSProfile, dict[str, Any]] = {
    CORSProfile.STRICT: {
        "allow_credentials": True,
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["Authorization", "Content-Type"],
        "max_age": 600,
    },
    CORSProfile.STANDARD: {
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "X-Request-ID"],
        "max_age": 3600,
    },
    CORSProfile.PERMISSIVE: {
        "allow_credentials": False,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        "allow_headers": ["*"],
        "max_age": 86400,
    },
}


class CORSManager:
    """Manages CORS rules per tenant/environment.

    Usage::

        manager = CORSManager(profile=CORSProfile.STANDARD)
        manager.add_origin("https://app.example.com")
        config = manager.check_origin("https://app.example.com")
        assert config.allowed
    """

    def __init__(self, profile: CORSProfile = CORSProfile.STANDARD) -> None:
        self.profile = profile
        self._rules: list[CORSRule] = []
        self._blocked_origins: set[str] = set()
        self._defaults = _PROFILE_DEFAULTS[profile]

    def add_origin(self, origin: str, **overrides: Any) -> None:
        """Add an allowed origin with optional overrides."""
        rule_kwargs = dict(self._defaults)
        rule_kwargs.update(overrides)
        self._rules.append(CORSRule(origin_pattern=origin, **rule_kwargs))

    def add_pattern(self, pattern: str, **overrides: Any) -> None:
        """Add a regex pattern for matching origins."""
        rule_kwargs = dict(self._defaults)
        rule_kwargs.update(overrides)
        self._rules.append(CORSRule(origin_pattern=pattern, **rule_kwargs))

    def block_origin(self, origin: str) -> None:
        self._blocked_origins.add(origin)

    def unblock_origin(self, origin: str) -> None:
        self._blocked_origins.discard(origin)

    def check_origin(self, origin: str) -> CORSConfig:
        """Check if an origin is allowed and return the CORS configuration."""
        if origin in self._blocked_origins:
            return CORSConfig(allowed=False, origin=origin)

        for rule in self._rules:
            if rule.origin_pattern == origin:
                return CORSConfig(
                    allowed=True, origin=origin,
                    allow_credentials=rule.allow_credentials,
                    allow_methods=rule.allow_methods,
                    allow_headers=rule.allow_headers,
                    max_age=rule.max_age,
                    expose_headers=rule.expose_headers,
                )
            try:
                if re.fullmatch(rule.origin_pattern, origin):
                    return CORSConfig(
                        allowed=True, origin=origin,
                        allow_credentials=rule.allow_credentials,
                        allow_methods=rule.allow_methods,
                        allow_headers=rule.allow_headers,
                        max_age=rule.max_age,
                        expose_headers=rule.expose_headers,
                    )
            except re.error:
                continue

        return CORSConfig(allowed=False, origin=origin)

    @property
    def allowed_origins(self) -> list[str]:
        return [r.origin_pattern for r in self._rules]

    def remove_origin(self, origin: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.origin_pattern != origin]
        return len(self._rules) < before

    def get_summary(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "allowed_origin_count": len(self._rules),
            "blocked_origin_count": len(self._blocked_origins),
            "origins": self.allowed_origins,
            "blocked": list(self._blocked_origins),
        }
