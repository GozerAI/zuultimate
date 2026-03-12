"""Redis connection manager with graceful in-memory fallback."""

import json
import time
from collections import defaultdict

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.redis")

# Optional redis import -- package may not be installed
try:
    import redis.asyncio as aioredis

    _HAS_REDIS = True
except ImportError:
    aioredis = None  # type: ignore[assignment]
    _HAS_REDIS = False


class RedisManager:
    """Thin wrapper around an async Redis connection with in-memory fallback.

    When the ``redis`` package is not installed or the server is unreachable the
    manager transparently degrades to a process-local dict so the application
    still functions (just without distributed state).
    """

    def __init__(self, url: str = "redis://localhost:6379/0"):
        self._url = url
        self._redis: "aioredis.Redis | None" = None  # type: ignore[name-defined]
        self._available = False
        # In-memory fallback stores
        self._mem_store: dict[str, str] = {}
        self._mem_expiry: dict[str, float] = {}
        self._mem_counters: dict[str, list[float]] = defaultdict(list)

    # ── lifecycle ──

    async def connect(self) -> None:
        if not _HAS_REDIS:
            _log.info("redis package not installed — using in-memory fallback")
            return
        try:
            self._redis = aioredis.from_url(
                self._url, decode_responses=True, socket_connect_timeout=2
            )
            await self._redis.ping()
            self._available = True
            _log.info("Connected to Redis at %s", self._url)
        except Exception as exc:
            _log.warning("Redis unavailable (%s) — using in-memory fallback", exc)
            self._redis = None
            self._available = False

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
        self._available = False

    @property
    def is_available(self) -> bool:
        return self._available

    # ── key/value operations ──

    async def get(self, key: str) -> str | None:
        if self._available and self._redis:
            return await self._redis.get(key)
        return self._mem_get(key)

    async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        if self._available and self._redis:
            await self._redis.setex(key, ttl_seconds, value)
            return
        self._mem_store[key] = value
        self._mem_expiry[key] = time.time() + ttl_seconds

    async def delete(self, key: str) -> None:
        if self._available and self._redis:
            await self._redis.delete(key)
            return
        self._mem_store.pop(key, None)
        self._mem_expiry.pop(key, None)

    # ── rate-limit helpers (sliding window) ──

    async def rate_limit_check(
        self, key: str, max_requests: int, window_seconds: int
    ) -> bool:
        """Return True if the request is allowed, False if rate-limited.

        Uses Redis sorted-set sliding window when available, else in-memory list.
        """
        if self._available and self._redis:
            return await self._redis_sliding_window(key, max_requests, window_seconds)
        return self._mem_sliding_window(key, max_requests, window_seconds)

    async def _redis_sliding_window(
        self, key: str, max_requests: int, window_seconds: int
    ) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        count = results[1]
        return count < max_requests

    def _mem_sliding_window(
        self, key: str, max_requests: int, window_seconds: int
    ) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        self._mem_counters[key] = [t for t in self._mem_counters[key] if t > cutoff]
        if len(self._mem_counters[key]) >= max_requests:
            return False
        self._mem_counters[key].append(now)
        return True

    # ── idempotency helpers ──

    async def get_idempotency(self, key: str) -> dict | None:
        raw = await self.get(f"idem:{key}")
        if raw is None:
            return None
        return json.loads(raw)

    async def store_idempotency(
        self, key: str, status_code: int, body: dict, ttl: int = 86400
    ) -> None:
        payload = json.dumps({"status_code": status_code, "body": body})
        await self.setex(f"idem:{key}", ttl, payload)

    # ── internal ──

    def _mem_get(self, key: str) -> str | None:
        expiry = self._mem_expiry.get(key)
        if expiry is not None and time.time() > expiry:
            self._mem_store.pop(key, None)
            self._mem_expiry.pop(key, None)
            return None
        return self._mem_store.get(key)

    def reset_all(self) -> None:
        """Clear all in-memory stores (for testing)."""
        self._mem_store.clear()
        self._mem_expiry.clear()
        self._mem_counters.clear()
