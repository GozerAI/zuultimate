"""In-process caching layers with TTL and invalidation support.

Items:
- #37: JWT validation result caching with TTL
- #44: API key validation cache with background refresh
- #59: RBAC permission cache per user
- #68: Vault secret cache with rotation-triggered invalidation
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.performance.caching")


# ─────────────────────────────────────────────────────────────────────────────
# Generic TTL cache
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _CacheEntry:
    value: Any
    expires_at: float
    created_at: float = field(default_factory=time.monotonic)


class TTLCache:
    """Simple in-process cache with per-entry TTL and max-size eviction."""

    def __init__(self, *, max_size: int = 2048, default_ttl: float = 60.0):
        self._store: dict[str, _CacheEntry] = {}
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None
        if time.monotonic() > entry.expires_at:
            del self._store[key]
            self._misses += 1
            return None
        self._hits += 1
        return entry.value

    def put(self, key: str, value: Any, ttl: float | None = None) -> None:
        if len(self._store) >= self._max_size:
            self._evict_expired()
        if len(self._store) >= self._max_size:
            # Evict oldest entry
            oldest_key = min(self._store, key=lambda k: self._store[k].created_at)
            del self._store[oldest_key]
        now = time.monotonic()
        self._store[key] = _CacheEntry(
            value=value,
            expires_at=now + (ttl if ttl is not None else self._default_ttl),
            created_at=now,
        )

    def invalidate(self, key: str) -> bool:
        return self._store.pop(key, None) is not None

    def invalidate_prefix(self, prefix: str) -> int:
        """Remove all entries whose key starts with the given prefix."""
        to_remove = [k for k in self._store if k.startswith(prefix)]
        for k in to_remove:
            del self._store[k]
        return len(to_remove)

    def clear(self) -> None:
        self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict[str, int]:
        return {"hits": self._hits, "misses": self._misses, "size": self.size}

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._store.items() if now > v.expires_at]
        for k in expired:
            del self._store[k]


# ─────────────────────────────────────────────────────────────────────────────
# #37  JWT validation result cache
# ─────────────────────────────────────────────────────────────────────────────

class JWTValidationCache:
    """Cache decoded JWT payloads keyed by token hash.

    Stores only *valid* decode results so subsequent requests with the same
    token skip the cryptographic verification.  TTL should be short (30-60s)
    to limit the window after revocation.
    """

    def __init__(self, *, ttl: float = 30.0, max_size: int = 4096):
        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)

    def _key(self, token: str) -> str:
        return f"jwt:{hashlib.sha256(token.encode()).hexdigest()[:24]}"

    def get(self, token: str) -> dict | None:
        return self._cache.get(self._key(token))

    def put(self, token: str, payload: dict) -> None:
        self._cache.put(self._key(token), payload)

    def invalidate(self, token: str) -> bool:
        return self._cache.invalidate(self._key(token))

    def invalidate_user(self, user_id: str) -> int:
        """Invalidate all cached tokens for a user (used on revocation)."""
        # Since keys are token hashes we can't reverse-map to user_id.
        # Instead, maintain a small side-index.
        removed = 0
        to_remove = []
        for k, entry in self._cache._store.items():
            if isinstance(entry.value, dict) and entry.value.get("sub") == user_id:
                to_remove.append(k)
        for k in to_remove:
            del self._cache._store[k]
            removed += 1
        return removed

    @property
    def stats(self) -> dict[str, int]:
        return self._cache.stats


# ─────────────────────────────────────────────────────────────────────────────
# #44  API key validation cache with background refresh
# ─────────────────────────────────────────────────────────────────────────────

class APIKeyCache:
    """Cache validated API key results with stale-while-revalidate semantics.

    On cache hit the caller gets an immediate response.  If the entry is within
    the soft-TTL window (``refresh_after``), a background task refreshes it
    so the next request sees fresh data.
    """

    def __init__(
        self,
        *,
        ttl: float = 300.0,
        refresh_after: float = 240.0,
        max_size: int = 2048,
    ):
        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)
        self._refresh_after = refresh_after
        self._refreshing: set[str] = set()

    def _key(self, key_prefix: str) -> str:
        return f"apikey:{key_prefix}"

    def get(self, key_prefix: str) -> dict | None:
        return self._cache.get(self._key(key_prefix))

    def needs_refresh(self, key_prefix: str) -> bool:
        """Return True if the entry exists but is past the soft-refresh window."""
        entry = self._cache._store.get(self._key(key_prefix))
        if entry is None:
            return False
        age = time.monotonic() - entry.created_at
        return age > self._refresh_after

    def put(self, key_prefix: str, result: dict) -> None:
        self._cache.put(self._key(key_prefix), result)

    def invalidate(self, key_prefix: str) -> bool:
        return self._cache.invalidate(self._key(key_prefix))

    def schedule_refresh(
        self,
        key_prefix: str,
        refresh_fn: Callable[[str], Awaitable[dict | None]],
    ) -> None:
        """Fire-and-forget background refresh if not already in progress."""
        cache_key = self._key(key_prefix)
        if cache_key in self._refreshing:
            return
        self._refreshing.add(cache_key)

        async def _do_refresh():
            try:
                result = await refresh_fn(key_prefix)
                if result is not None:
                    self.put(key_prefix, result)
            except Exception:
                _log.debug("Background API key refresh failed for %s", key_prefix)
            finally:
                self._refreshing.discard(cache_key)

        asyncio.create_task(_do_refresh())

    @property
    def stats(self) -> dict[str, int]:
        return self._cache.stats


# ─────────────────────────────────────────────────────────────────────────────
# #59  RBAC permission cache per user
# ─────────────────────────────────────────────────────────────────────────────

class RBACPermissionCache:
    """Cache RBAC access-check results per user+resource+action triple.

    Invalidated on role assignment changes.  TTL keeps the window bounded.
    """

    def __init__(self, *, ttl: float = 120.0, max_size: int = 4096):
        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)

    def _key(self, user_id: str, resource: str, action: str) -> str:
        return f"rbac:{user_id}:{resource}:{action}"

    def get(self, user_id: str, resource: str, action: str) -> dict | None:
        return self._cache.get(self._key(user_id, resource, action))

    def put(self, user_id: str, resource: str, action: str, result: dict) -> None:
        self._cache.put(self._key(user_id, resource, action), result)

    def invalidate_user(self, user_id: str) -> int:
        """Clear all cached permissions for a user (e.g., after role change)."""
        return self._cache.invalidate_prefix(f"rbac:{user_id}:")

    def clear(self) -> None:
        self._cache.clear()

    @property
    def stats(self) -> dict[str, int]:
        return self._cache.stats


# ─────────────────────────────────────────────────────────────────────────────
# #68  Vault secret cache with rotation-triggered invalidation
# ─────────────────────────────────────────────────────────────────────────────

class VaultSecretCache:
    """Cache decrypted vault secrets with rotation-triggered invalidation.

    When a key rotation occurs, ``on_rotation()`` clears the entire cache
    since all cached decryptions are now stale.
    """

    def __init__(self, *, ttl: float = 60.0, max_size: int = 1024):
        self._cache = TTLCache(max_size=max_size, default_ttl=ttl)
        self._rotation_generation = 0

    def _key(self, blob_id: str, owner_id: str) -> str:
        return f"vault:{self._rotation_generation}:{blob_id}:{owner_id}"

    def get(self, blob_id: str, owner_id: str = "") -> dict | None:
        return self._cache.get(self._key(blob_id, owner_id))

    def put(self, blob_id: str, owner_id: str, result: dict) -> None:
        self._cache.put(self._key(blob_id, owner_id), result)

    def invalidate(self, blob_id: str, owner_id: str = "") -> bool:
        return self._cache.invalidate(self._key(blob_id, owner_id))

    def on_rotation(self) -> None:
        """Called when vault key rotation occurs.  Clears all cached secrets."""
        self._rotation_generation += 1
        self._cache.clear()
        _log.info(
            "Vault secret cache cleared due to rotation (gen=%d)",
            self._rotation_generation,
        )

    @property
    def stats(self) -> dict[str, int]:
        return {**self._cache.stats, "rotation_generation": self._rotation_generation}
