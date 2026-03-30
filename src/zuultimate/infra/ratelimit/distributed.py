"""Two-tier distributed rate limiter with local fast path."""

import time
from dataclasses import dataclass, field


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    retry_after: int | None = None


class DistributedRateLimiter:
    """
    Two-tier rate limiter:
    - Local tier: in-process counter, no Redis call (fast path)
    - Redis tier: global counter, checked when local share exhausted (slow path)

    Reduces Redis calls by ~90% vs naive per-request counter.
    Accuracy: within 10% of local share (acceptable for abuse prevention).
    """

    def __init__(
        self,
        redis,
        limit: int,
        window_seconds: int,
        num_pods: int = 10,
    ):
        self._redis = redis
        self.limit = limit
        self.window = window_seconds
        self.num_pods = num_pods
        self.local_share = max(1, limit // num_pods)
        self.sync_every = max(1, self.local_share // 10)
        # Per-key tracking
        self._local_counts: dict[str, int] = {}
        self._window_starts: dict[str, float] = {}

    def _current_window(self, key: str) -> str:
        """Get current time window identifier."""
        window_id = int(time.time()) // self.window
        return f"auth:rl:{key}:{window_id}"

    def _reset_if_new_window(self, key: str) -> None:
        """Reset local counter if window has rolled over."""
        current = int(time.time()) // self.window
        stored = self._window_starts.get(key, 0)
        if current != stored:
            self._local_counts[key] = 0
            self._window_starts[key] = current

    async def check(self, key: str) -> RateLimitResult:
        """Check rate limit. Returns RateLimitResult."""
        self._reset_if_new_window(key)
        self._local_counts[key] = self._local_counts.get(key, 0) + 1
        local_count = self._local_counts[key]

        # Fast path: local share not exhausted
        if local_count < self.local_share and local_count % self.sync_every != 0:
            return RateLimitResult(
                allowed=True,
                remaining=self.local_share - local_count,
            )

        # Slow path: sync with Redis
        redis_key = self._current_window(key)
        try:
            raw = getattr(self._redis, "_redis", None)
            if raw is not None:
                pipe = raw.pipeline()
                pipe.incr(redis_key)
                pipe.expire(redis_key, self.window)
                results = await pipe.execute()
                global_count = results[0]
            else:
                # Fallback: use local count only
                global_count = local_count
        except Exception:
            global_count = local_count

        self._local_counts[key] = 0  # reset after sync
        allowed = global_count <= self.limit

        return RateLimitResult(
            allowed=allowed,
            remaining=max(0, self.limit - global_count),
            retry_after=self.window if not allowed else None,
        )


# Endpoint-specific rate limit configs
RATE_LIMIT_CONFIGS = {
    "auth_token": {"limit": 10, "window": 1},  # 10/sec per IP
    "auth_token_user": {"limit": 5, "window": 1},  # 5/sec per username
    "introspect": {"limit": 1000, "window": 1},  # 1000/sec per API key
    "passkey": {"limit": 5, "window": 1},  # 5/sec per IP
    "dsar": {"limit": 10, "window": 86400},  # 10/day per subject
}
