"""Offline authentication with cached tokens.

When the main identity service or database is unreachable, this module validates
JWT tokens against a local cache of public keys and token metadata, enabling
continued operation in disconnected environments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class OfflineAuthStatus(str, Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    CACHE_MISS = "cache_miss"


@dataclass
class CachedToken:
    """A locally cached token with metadata for offline validation."""
    token_hash: str
    user_id: str
    tenant_id: str
    username: str
    roles: list[str]
    issued_at: float
    expires_at: float
    revoked: bool = False
    last_verified_online: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def time_since_online_check(self) -> float:
        if self.last_verified_online == 0:
            return float("inf")
        return time.time() - self.last_verified_online


@dataclass
class OfflineAuthResult:
    status: OfflineAuthStatus
    user_id: str = ""
    tenant_id: str = ""
    username: str = ""
    roles: list[str] = field(default_factory=list)
    offline_mode: bool = True
    cache_age_seconds: float = 0.0
    message: str = ""


class OfflineAuthenticator:
    """Validates tokens offline using a local cache.

    Tokens are cached after successful online authentication. When the system
    goes offline, cached tokens are validated locally with configurable
    staleness thresholds.

    Usage::

        auth = OfflineAuthenticator(max_cache_age_hours=24)
        auth.cache_token("abc123", user_id="u1", tenant_id="t1", ...)
        result = auth.validate("abc123")
    """

    def __init__(
        self,
        max_cache_age_hours: float = 24,
        max_cache_entries: int = 10000,
        secret_key: str = "",
    ) -> None:
        self.max_cache_age_hours = max_cache_age_hours
        self.max_cache_entries = max_cache_entries
        self._secret_key = secret_key
        self._cache: dict[str, CachedToken] = {}
        self._revoked_tokens: set[str] = set()

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def cache_token(
        self,
        token: str,
        user_id: str,
        tenant_id: str,
        username: str,
        roles: list[str] | None = None,
        expires_at: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CachedToken:
        """Cache a token after successful online validation."""
        token_hash = self._hash_token(token)

        # Evict oldest if at capacity
        if len(self._cache) >= self.max_cache_entries:
            oldest_key = min(self._cache, key=lambda k: self._cache[k].issued_at)
            del self._cache[oldest_key]

        entry = CachedToken(
            token_hash=token_hash,
            user_id=user_id, tenant_id=tenant_id,
            username=username, roles=roles or [],
            issued_at=time.time(),
            expires_at=expires_at or (time.time() + self.max_cache_age_hours * 3600),
            last_verified_online=time.time(),
            metadata=metadata or {},
        )
        self._cache[token_hash] = entry
        return entry

    def validate(self, token: str) -> OfflineAuthResult:
        """Validate a token offline using the local cache."""
        token_hash = self._hash_token(token)

        if token_hash in self._revoked_tokens:
            return OfflineAuthResult(
                status=OfflineAuthStatus.REVOKED,
                message="Token has been revoked",
            )

        entry = self._cache.get(token_hash)
        if entry is None:
            return OfflineAuthResult(
                status=OfflineAuthStatus.CACHE_MISS,
                message="Token not found in offline cache",
            )

        if entry.revoked:
            return OfflineAuthResult(
                status=OfflineAuthStatus.REVOKED,
                user_id=entry.user_id, tenant_id=entry.tenant_id,
                username=entry.username,
                message="Token has been revoked",
            )

        if entry.is_expired:
            return OfflineAuthResult(
                status=OfflineAuthStatus.EXPIRED,
                user_id=entry.user_id, tenant_id=entry.tenant_id,
                username=entry.username,
                message="Token has expired",
            )

        cache_age = entry.time_since_online_check
        max_age_seconds = self.max_cache_age_hours * 3600

        if cache_age > max_age_seconds:
            return OfflineAuthResult(
                status=OfflineAuthStatus.EXPIRED,
                user_id=entry.user_id, tenant_id=entry.tenant_id,
                username=entry.username,
                cache_age_seconds=cache_age,
                message=f"Cache entry too stale ({cache_age / 3600:.1f}h old)",
            )

        return OfflineAuthResult(
            status=OfflineAuthStatus.VALID,
            user_id=entry.user_id, tenant_id=entry.tenant_id,
            username=entry.username, roles=entry.roles,
            offline_mode=True, cache_age_seconds=cache_age,
            message="Token validated offline",
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke a token in the offline cache."""
        token_hash = self._hash_token(token)
        self._revoked_tokens.add(token_hash)
        entry = self._cache.get(token_hash)
        if entry:
            entry.revoked = True
            return True
        return False

    def refresh_online_check(self, token: str) -> bool:
        """Mark a token as recently verified online."""
        token_hash = self._hash_token(token)
        entry = self._cache.get(token_hash)
        if entry:
            entry.last_verified_online = time.time()
            return True
        return False

    def evict_expired(self) -> int:
        """Remove all expired entries from cache."""
        expired = [h for h, e in self._cache.items() if e.is_expired]
        for h in expired:
            del self._cache[h]
        return len(expired)

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def get_summary(self) -> dict[str, Any]:
        entries = list(self._cache.values())
        return {
            "cache_size": len(entries),
            "revoked_count": len(self._revoked_tokens),
            "expired_count": sum(1 for e in entries if e.is_expired),
            "active_count": sum(1 for e in entries if not e.is_expired and not e.revoked),
            "max_cache_entries": self.max_cache_entries,
            "max_cache_age_hours": self.max_cache_age_hours,
        }
