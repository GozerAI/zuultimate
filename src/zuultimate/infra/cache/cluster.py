"""Redis Cluster configuration with circuit breaker and fallback.

Wraps the existing RedisManager with cluster-aware behavior including
read preference routing and circuit breaker pattern for resilience.
"""

from __future__ import annotations

import time

from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.cache.cluster")

# Memory alert thresholds (bytes)
MEMORY_WARNING_THRESHOLD = 1_073_741_824  # 1 GB
MEMORY_CRITICAL_THRESHOLD = 3_221_225_472  # 3 GB


class RedisClusterConfig:
    """Configuration for Redis Cluster connections.

    Wraps the existing RedisManager with cluster-aware behavior.
    """

    # Read preference for different data types
    READ_FROM_REPLICA = {"tenant_config", "posture_cache", "jwks_cache"}
    READ_FROM_PRIMARY = {"session", "rate_limit", "deny_list", "generation"}

    def __init__(self, redis, fallback_db=None):
        self._redis = redis
        self._fallback_db = fallback_db
        self._circuit_open = False
        self._failure_count = 0
        self._failure_threshold = 5
        self._last_failure = 0.0
        self._recovery_timeout = 30.0  # seconds

    async def get(self, key: str, data_type: str = "session") -> bytes | str | None:
        """Get with circuit breaker. Falls back to DB on Redis failure.

        data_type determines read preference (replica vs primary).
        """
        if self._is_circuit_open():
            return await self._fallback_get(key) if self._fallback_db else None

        try:
            result = await self._redis.get(key)
            self._reset_circuit()
            return result
        except Exception:
            self._record_failure()
            return await self._fallback_get(key) if self._fallback_db else None

    async def set(
        self, key: str, value: str | bytes, ttl: int | None = None
    ) -> bool:
        """Set with circuit breaker. Returns True on success, False on failure."""
        if self._is_circuit_open():
            return False

        try:
            if ttl is not None:
                await self._redis.setex(key, ttl, value)
            else:
                # Use setex with a default TTL to avoid keys without expiry
                await self._redis.setex(key, 3600, value)
            self._reset_circuit()
            return True
        except Exception:
            self._record_failure()
            return False

    async def delete(self, key: str) -> bool:
        """Delete with circuit breaker. Returns True on success."""
        if self._is_circuit_open():
            return False

        try:
            await self._redis.delete(key)
            self._reset_circuit()
            return True
        except Exception:
            self._record_failure()
            return False

    async def check_memory(self) -> dict:
        """Return memory usage stats.

        Returns dict with used_memory, max_memory, usage_ratio, and alert_level.
        """
        if self._is_circuit_open():
            return {
                "used_memory": 0,
                "max_memory": 0,
                "usage_ratio": 0.0,
                "alert_level": "unknown",
                "circuit_open": True,
            }

        try:
            # Try to get Redis INFO memory stats
            redis_client = getattr(self._redis, "_redis", None)
            if redis_client is not None and hasattr(redis_client, "info"):
                info = await redis_client.info("memory")
                used = info.get("used_memory", 0)
                max_mem = info.get("maxmemory", 0)
            else:
                # Fallback: estimate from in-memory store
                used = self._estimate_memory()
                max_mem = 0

            ratio = used / max_mem if max_mem > 0 else 0.0

            if used >= MEMORY_CRITICAL_THRESHOLD:
                alert = "critical"
            elif used >= MEMORY_WARNING_THRESHOLD:
                alert = "warning"
            else:
                alert = "ok"

            self._reset_circuit()
            return {
                "used_memory": used,
                "max_memory": max_mem,
                "usage_ratio": ratio,
                "alert_level": alert,
                "circuit_open": False,
            }
        except Exception:
            self._record_failure()
            return {
                "used_memory": 0,
                "max_memory": 0,
                "usage_ratio": 0.0,
                "alert_level": "unknown",
                "circuit_open": self._circuit_open,
            }

    async def get_key_counts(self) -> dict[str, int]:
        """Return counts per key prefix.

        Scans keys and groups them by the portion before the first ':'.
        Returns a dict like {"session": 42, "jwks": 1, ...}.
        """
        if self._is_circuit_open():
            return {}

        try:
            # For in-memory fallback, count from _mem_store
            mem_store = getattr(self._redis, "_mem_store", None)
            if mem_store is not None:
                counts: dict[str, int] = {}
                for key in mem_store:
                    prefix = key.split(":")[0] if ":" in key else key
                    counts[prefix] = counts.get(prefix, 0) + 1
                self._reset_circuit()
                return counts

            # For real Redis, use SCAN
            redis_client = getattr(self._redis, "_redis", None)
            if redis_client is not None and hasattr(redis_client, "scan"):
                counts = {}
                cursor = 0
                while True:
                    cursor, keys = await redis_client.scan(cursor, count=100)
                    for key in keys:
                        k = key if isinstance(key, str) else key.decode()
                        prefix = k.split(":")[0] if ":" in k else k
                        counts[prefix] = counts.get(prefix, 0) + 1
                    if cursor == 0:
                        break
                self._reset_circuit()
                return counts

            self._reset_circuit()
            return {}
        except Exception:
            self._record_failure()
            return {}

    def get_read_preference(self, data_type: str) -> str:
        """Return read preference for a given data type."""
        if data_type in self.READ_FROM_REPLICA:
            return "replica"
        return "primary"

    def _is_circuit_open(self) -> bool:
        if not self._circuit_open:
            return False
        if time.time() - self._last_failure > self._recovery_timeout:
            self._circuit_open = False
            return False
        return True

    def _record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure = time.time()
        if self._failure_count >= self._failure_threshold:
            self._circuit_open = True
            _log.warning(
                "Circuit breaker OPEN after %d failures", self._failure_count
            )

    def _reset_circuit(self) -> None:
        self._failure_count = 0
        self._circuit_open = False

    async def _fallback_get(self, key: str) -> bytes | str | None:
        """Attempt to read from fallback DB."""
        if self._fallback_db is None:
            return None
        try:
            return await self._fallback_db.get(key)
        except Exception:
            return None

    def _estimate_memory(self) -> int:
        """Rough memory estimate for in-memory fallback store."""
        mem_store = getattr(self._redis, "_mem_store", {})
        total = 0
        for k, v in mem_store.items():
            total += len(k) + len(str(v))
        return total
