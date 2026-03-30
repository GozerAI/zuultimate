"""JWKS key rotation lifecycle — stampede-free 48-hour rotation cycle.

Manages the full 48-hour key rotation cycle:

T-24hrs: New key generated, added to JWKS as PENDING (both keys served)
T-0:     New key activated for issuance, old key moves to RETIRING
T+24hrs: Old key removed (RETIRED), only new key in use

This eliminates thundering herd on JWKS endpoint during rotation.
Services naturally cache the new key before it's activated for signing.
"""

from __future__ import annotations

from zuultimate.common.key_manager import (
    ACTIVE,
    PENDING,
    RETIRED,
    RETIRING,
    JWKSKey,
    KeyManager,
    _generate_kid,
    _generate_rsa_key_pair,
)
from zuultimate.common.logging import get_logger

from datetime import datetime, timedelta, timezone
from sqlalchemy import select

_log = get_logger("zuultimate.jwks.rotation")

# Short cache TTL applied during rotation transitions (seconds)
ROTATION_CACHE_TTL = 5
# Normal JWKS cache TTL (seconds)
NORMAL_CACHE_TTL = 60


class KeyRotationLifecycle:
    """Manages the full 48-hour key rotation cycle."""

    STATUS_PENDING = PENDING
    STATUS_ACTIVE = ACTIVE
    STATUS_RETIRING = RETIRING
    STATUS_RETIRED = RETIRED

    def __init__(self, key_manager: KeyManager, redis=None):
        self._km = key_manager
        self._redis = redis

    async def initiate_rotation(self) -> dict:
        """Step 1: Generate new key as PENDING. Both keys now served in JWKS.

        Returns info about the rotation in progress.
        """
        db = self._km.db
        region = self._km.region

        private_pem, public_pem = _generate_rsa_key_pair()
        kid = _generate_kid(public_pem)

        async with db.get_session("identity") as session:
            # Check no PENDING key already exists
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == PENDING)
            )
            existing = result.scalar_one_or_none()
            if existing is not None:
                return {
                    "status": "already_pending",
                    "pending_kid": existing.kid,
                    "message": "A rotation is already in progress",
                }

            new_key = JWKSKey(
                kid=kid,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                status=PENDING,
                region=region,
                expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            )
            session.add(new_key)

        self._km._invalidate_cache()
        await self._set_short_cache_ttl()

        _log.info("Rotation initiated — PENDING key kid=%s", kid)
        return {
            "status": "initiated",
            "pending_kid": kid,
            "message": "New key added as PENDING. Activate after 24h pre-announcement.",
        }

    async def activate_new_key(self, new_kid: str) -> dict:
        """Step 2: Promote PENDING key to ACTIVE, demote current ACTIVE to RETIRING.

        Called after 24-hour pre-announcement window.
        """
        db = self._km.db

        async with db.get_session("identity") as session:
            # Find the PENDING key
            result = await session.execute(
                select(JWKSKey).where(
                    JWKSKey.kid == new_kid, JWKSKey.status == PENDING
                )
            )
            pending_key = result.scalar_one_or_none()
            if pending_key is None:
                return {
                    "status": "error",
                    "message": f"No PENDING key found with kid={new_kid}",
                }

            # Demote current ACTIVE → RETIRING
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == ACTIVE)
            )
            for key in result.scalars().all():
                key.status = RETIRING
                _log.info("Key kid=%s moved ACTIVE → RETIRING", key.kid)

            # Promote PENDING → ACTIVE
            pending_key.status = ACTIVE
            _log.info("Key kid=%s promoted PENDING → ACTIVE", new_kid)

        self._km._invalidate_cache()
        await self._set_short_cache_ttl()

        return {
            "status": "activated",
            "active_kid": new_kid,
            "message": "New key is now ACTIVE for signing. Retire old key after 24h.",
        }

    async def retire_old_key(self, old_kid: str) -> dict:
        """Step 3: Move RETIRING key to RETIRED (removed from JWKS).

        Called after 24-hour overlap window.
        """
        db = self._km.db

        async with db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(
                    JWKSKey.kid == old_kid, JWKSKey.status == RETIRING
                )
            )
            retiring_key = result.scalar_one_or_none()
            if retiring_key is None:
                return {
                    "status": "error",
                    "message": f"No RETIRING key found with kid={old_kid}",
                }

            retiring_key.status = RETIRED
            _log.info("Key kid=%s moved RETIRING → RETIRED", old_kid)

        self._km._invalidate_cache()
        await self._set_short_cache_ttl()

        return {
            "status": "retired",
            "retired_kid": old_kid,
            "message": "Old key retired and removed from JWKS.",
        }

    async def get_rotation_status(self) -> dict:
        """Get current state of all keys and any in-progress rotation."""
        db = self._km.db

        async with db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status != RETIRED)
            )
            keys = result.scalars().all()

        key_info = []
        for k in keys:
            key_info.append({
                "kid": k.kid,
                "status": k.status,
                "region": k.region,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            })

        has_pending = any(k["status"] == PENDING for k in key_info)
        has_retiring = any(k["status"] == RETIRING for k in key_info)

        if has_pending:
            rotation_phase = "pre-announcement"
        elif has_retiring:
            rotation_phase = "overlap"
        else:
            rotation_phase = "stable"

        return {
            "rotation_phase": rotation_phase,
            "keys": key_info,
        }

    async def _set_short_cache_ttl(self) -> None:
        """Briefly set JWKS cache to short TTL so CDN picks up changes faster."""
        if self._redis is None:
            return
        redis = self._redis
        if not getattr(redis, "is_available", False):
            return

        # Delete existing cache so next fetch rebuilds it
        try:
            await redis.delete("jwks:cache")
        except Exception:
            pass
