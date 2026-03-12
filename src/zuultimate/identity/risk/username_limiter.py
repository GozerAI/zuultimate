"""Per-username rate limiter independent of IP-based limits."""

from zuultimate.common.redis import RedisManager


class UsernameLimiter:
    """Enforce per-username request limits using a sliding window.

    Operates independently of IP-based rate limiting to provide a
    complementary defense against credential stuffing attacks.
    """

    def __init__(self, redis: RedisManager) -> None:
        self.redis = redis

    async def check(
        self,
        username_hash: str,
        max_attempts: int = 10,
        window_seconds: int = 300,
    ) -> bool:
        """Return True if under the rate limit, False if blocked."""
        key = f"ratelimit:user:{username_hash}"
        return await self.redis.rate_limit_check(key, max_attempts, window_seconds)
