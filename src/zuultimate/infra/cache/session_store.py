"""Redis-backed session store with generation-based revocation.

All active session state lives in Redis so the database is never on the
hot authentication path.  When Redis is unavailable every read returns
``None`` and every write is a silent no-op (graceful degradation).
"""

from __future__ import annotations

import json
from typing import Any

from zuultimate.common.logging import get_logger
from zuultimate.common.redis import RedisManager

_log = get_logger("zuultimate.infra.cache.session_store")


class RedisSessionStore:
    """All active session state in Redis.  DB is never on hot auth path."""

    KEY_SESSION = "auth:session:{jti}"  # TTL = token_expiry
    KEY_GEN = "auth:gen:{user_id}"  # generation counter
    KEY_DENY = "auth:denylist:{uid}:{gen}"  # per-gen deny set
    KEY_POSTURE = "auth:posture:{device_id}"  # TTL = 5 min
    KEY_TENANT = "config:tenant:{tenant_id}"  # TTL = 5 min
    KEY_FAMILY = "auth:family:{fid}"  # refresh token family

    def __init__(self, redis: RedisManager) -> None:
        self._redis = redis

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    async def create_session(
        self, jti: str, claims: dict[str, Any], ttl_seconds: int
    ) -> None:
        """Store session in Redis with TTL."""
        key = self.KEY_SESSION.format(jti=jti)
        try:
            await self._redis.setex(key, ttl_seconds, json.dumps(claims))
        except Exception:
            _log.debug("Redis unavailable — session not cached")

    async def get_session(self, jti: str) -> dict[str, Any] | None:
        """Retrieve session from Redis."""
        key = self.KEY_SESSION.format(jti=jti)
        try:
            raw = await self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            _log.debug("Redis unavailable — session cache miss")
            return None

    async def delete_session(self, jti: str) -> None:
        """Remove session from Redis."""
        key = self.KEY_SESSION.format(jti=jti)
        try:
            await self._redis.delete(key)
        except Exception:
            _log.debug("Redis unavailable — session delete skipped")

    # ------------------------------------------------------------------
    # Generation-based revocation
    # ------------------------------------------------------------------

    async def get_generation(self, user_id: str) -> int:
        """Get current generation counter for a user (defaults to 0)."""
        key = self.KEY_GEN.format(user_id=user_id)
        try:
            raw = await self._redis.get(key)
            if raw is None:
                return 0
            return int(raw)
        except Exception:
            _log.debug("Redis unavailable — defaulting generation to 0")
            return 0

    async def revoke_all_sessions(self, user_id: str) -> None:
        """Increment generation counter — one write = all sessions invalid."""
        key = self.KEY_GEN.format(user_id=user_id)
        try:
            current = await self.get_generation(user_id)
            new_gen = current + 1
            # Store without expiry (generation persists)
            # Use a very long TTL (30 days) to avoid infinite retention
            await self._redis.setex(key, 30 * 24 * 3600, str(new_gen))
        except Exception:
            _log.debug("Redis unavailable — revoke_all skipped")

    async def revoke_session(self, user_id: str, jti: str, gen: int) -> None:
        """Add jti to per-generation deny set."""
        key = self.KEY_DENY.format(uid=user_id, gen=gen)
        try:
            # Store as JSON list — append to existing
            raw = await self._redis.get(key)
            denied: list[str] = json.loads(raw) if raw else []
            if jti not in denied:
                denied.append(jti)
            # TTL matches the generation lifecycle (24h)
            await self._redis.setex(key, 24 * 3600, json.dumps(denied))
        except Exception:
            _log.debug("Redis unavailable — session revoke skipped")

    async def is_session_denied(self, user_id: str, jti: str, gen: int) -> bool:
        """Check if jti is in the per-generation deny set."""
        key = self.KEY_DENY.format(uid=user_id, gen=gen)
        try:
            raw = await self._redis.get(key)
            if raw is None:
                return False
            denied: list[str] = json.loads(raw)
            return jti in denied
        except Exception:
            _log.debug("Redis unavailable — deny check skipped")
            return False

    async def validate_token_session(
        self, user_id: str, jti: str, gen: int
    ) -> bool:
        """Combined validation: generation check + deny check + session existence.

        Returns True if the token session is valid, False otherwise.
        Returns True also when Redis is unavailable (caller should fall back to DB).
        """
        try:
            # 1. Check generation counter — if token's gen is behind current,
            #    the token was issued before a revoke-all and is invalid.
            current_gen = await self.get_generation(user_id)
            if gen < current_gen:
                return False

            # 2. Check per-generation deny set
            if await self.is_session_denied(user_id, jti, gen):
                return False

            # 3. Check session exists in Redis
            session = await self.get_session(jti)
            if session is None:
                # Session not in Redis — could mean expired or never cached.
                # Return False so caller can decide to fall back to DB.
                return False

            return True
        except Exception:
            _log.debug("Redis unavailable — validate_token_session indeterminate")
            # Cannot determine — signal caller to fall back to DB
            raise

    # ------------------------------------------------------------------
    # Tenant config cache
    # ------------------------------------------------------------------

    async def cache_tenant(
        self, tenant_id: str, data: dict[str, Any], ttl: int = 300
    ) -> None:
        """Cache tenant configuration."""
        key = self.KEY_TENANT.format(tenant_id=tenant_id)
        try:
            await self._redis.setex(key, ttl, json.dumps(data))
        except Exception:
            _log.debug("Redis unavailable — tenant not cached")

    async def get_cached_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        """Get cached tenant configuration."""
        key = self.KEY_TENANT.format(tenant_id=tenant_id)
        try:
            raw = await self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            _log.debug("Redis unavailable — tenant cache miss")
            return None

    async def invalidate_tenant(self, tenant_id: str) -> None:
        """Delete cached tenant configuration."""
        key = self.KEY_TENANT.format(tenant_id=tenant_id)
        try:
            await self._redis.delete(key)
        except Exception:
            _log.debug("Redis unavailable — tenant invalidation skipped")

    # ------------------------------------------------------------------
    # Device posture cache
    # ------------------------------------------------------------------

    async def cache_posture(
        self, device_id: str, data: dict[str, Any], ttl: int = 300
    ) -> None:
        """Cache device posture assessment."""
        key = self.KEY_POSTURE.format(device_id=device_id)
        try:
            await self._redis.setex(key, ttl, json.dumps(data))
        except Exception:
            _log.debug("Redis unavailable — posture not cached")

    async def get_cached_posture(self, device_id: str) -> dict[str, Any] | None:
        """Get cached device posture."""
        key = self.KEY_POSTURE.format(device_id=device_id)
        try:
            raw = await self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            _log.debug("Redis unavailable — posture cache miss")
            return None
