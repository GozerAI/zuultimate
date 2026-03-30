"""Progressive auth lockout -- tracks failed attempts per IP and per account."""

import hashlib

from zuultimate.common.logging import get_logger
from zuultimate.common.redis import RedisManager

_log = get_logger("zuultimate.lockout")

# Progressive thresholds: (failure_count, cooldown_seconds)
_THRESHOLDS = [
    (20, 900),   # 20 failures -> 15 minutes
    (10, 300),   # 10 failures -> 5 minutes
    (5, 30),     # 5 failures  -> 30 seconds
]

# Sliding window for counting failures (1 hour)
_WINDOW_SECONDS = 3600


def _hash(value: str) -> str:
    """Return SHA-256 hex digest of a value."""
    return hashlib.sha256(value.encode()).hexdigest()


class LockoutService:
    """Track failed auth attempts per IP and per account with progressive cooldowns.

    Uses Redis (with in-memory fallback) for lockout state and attempt counting.
    """

    def __init__(self, redis: RedisManager) -> None:
        self._redis = redis

    async def check_lockout(self, ip: str, username: str) -> tuple[bool, int]:
        """Check whether the given IP or username is currently locked out.

        Return a tuple of (is_locked, remaining_seconds). When not locked out
        remaining_seconds is 0.
        """
        ip_hash = _hash(ip)
        user_hash = _hash(username)

        ip_remaining = await self._get_remaining(f"lockout:ip:{ip_hash}")
        user_remaining = await self._get_remaining(f"lockout:user:{user_hash}")

        remaining = max(ip_remaining, user_remaining)
        if remaining > 0:
            return True, remaining
        return False, 0

    async def record_failure(self, ip: str, username: str) -> None:
        """Record a failed auth attempt and apply lockout if a threshold is reached."""
        ip_hash = _hash(ip)
        user_hash = _hash(username)

        ip_key = f"auth_fail:ip:{ip_hash}"
        user_key = f"auth_fail:user:{user_hash}"

        # Add an entry to the sliding window (rate_limit_check returns False
        # when the limit is exceeded, but we use a very high limit here just
        # to record the timestamp; the actual threshold logic follows).
        await self._redis.rate_limit_check(ip_key, 10000, _WINDOW_SECONDS)
        await self._redis.rate_limit_check(user_key, 10000, _WINDOW_SECONDS)

        ip_count = self._count_entries(ip_key)
        user_count = self._count_entries(user_key)

        # Apply lockout based on the higher count
        count = max(ip_count, user_count)
        cooldown = self._cooldown_for(count)
        if cooldown > 0:
            await self._redis.setex(f"lockout:ip:{ip_hash}", cooldown, "1")
            await self._redis.setex(f"lockout:user:{user_hash}", cooldown, "1")
            _log.warning(
                "lockout triggered: count=%d cooldown=%ds ip=%s...",
                count,
                cooldown,
                ip_hash[:8],
            )

    async def record_success(self, ip: str, username: str) -> None:
        """Clear failure counters and lockout state after a successful auth."""
        ip_hash = _hash(ip)
        user_hash = _hash(username)

        # Clear lockout keys
        await self._redis.delete(f"lockout:ip:{ip_hash}")
        await self._redis.delete(f"lockout:user:{user_hash}")

        # Clear counter sliding-window entries
        self._clear_counter(f"auth_fail:ip:{ip_hash}")
        self._clear_counter(f"auth_fail:user:{user_hash}")

    # -- internals --

    async def _get_remaining(self, key: str) -> int:
        """Return the remaining lockout seconds for a key, or 0 if not locked."""
        val = await self._redis.get(key)
        if val is None:
            return 0
        # In-memory fallback stores expiry timestamps we can inspect
        import time

        expiry = self._redis._mem_expiry.get(key)
        if expiry is not None:
            remaining = int(expiry - time.time())
            return max(remaining, 1)
        # When using real Redis we know the key exists so at least 1s remains
        return 1

    def _count_entries(self, key: str) -> int:
        """Count entries in the in-memory sliding-window counter."""
        import time

        now = time.time()
        cutoff = now - _WINDOW_SECONDS
        entries = self._redis._mem_counters.get(key, [])
        return len([t for t in entries if t > cutoff])

    @staticmethod
    def _cooldown_for(count: int) -> int:
        """Return the cooldown seconds for a given failure count, or 0."""
        for threshold, cooldown in _THRESHOLDS:
            if count >= threshold:
                return cooldown
        return 0

    def _clear_counter(self, key: str) -> None:
        """Remove all entries from an in-memory sliding-window counter."""
        self._redis._mem_counters.pop(key, None)
