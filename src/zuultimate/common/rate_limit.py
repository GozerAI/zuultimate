"""Rate limiter backed by Redis (or in-memory fallback)."""

from fastapi import HTTPException, Request

from zuultimate.common.redis import RedisManager


class RateLimiter:
    """Sliding-window rate limiter backed by RedisManager."""

    def __init__(
        self,
        redis: RedisManager,
        max_requests: int = 10,
        window_seconds: int = 300,
        prefix: str = "rl",
    ):
        self._redis = redis
        self.max_requests = max_requests
        self.window = window_seconds
        self._prefix = prefix

    async def check(self, key: str) -> None:
        full_key = f"{self._prefix}:{key}"
        allowed = await self._redis.rate_limit_check(
            full_key, self.max_requests, self.window
        )
        if not allowed:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")


async def rate_limit_login(request: Request) -> None:
    """Dependency that rate-limits login attempts by client IP."""
    redis: RedisManager = request.app.state.redis
    limiter = RateLimiter(redis, max_requests=10, window_seconds=300, prefix="login")
    client_ip = request.client.host if request.client else "unknown"
    await limiter.check(client_ip)
