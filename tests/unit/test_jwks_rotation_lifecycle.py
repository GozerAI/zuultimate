"""Tests for JWKS rotation lifecycle — stampede-free 48-hour key rotation."""

import pytest

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.key_manager import (
    ACTIVE,
    PENDING,
    RETIRED,
    RETIRING,
    JWKSKey,
    KeyManager,
)
from zuultimate.infra.jwks.rotation import KeyRotationLifecycle

from sqlalchemy import select

_IN_MEMORY = "sqlite+aiosqlite://"


@pytest.fixture
async def km_db():
    import zuultimate.common.key_manager  # noqa: F401

    settings = ZuulSettings(
        identity_db_url=_IN_MEMORY,
        credential_db_url=_IN_MEMORY,
        session_db_url=_IN_MEMORY,
        transaction_db_url=_IN_MEMORY,
        audit_db_url=_IN_MEMORY,
        crm_db_url=_IN_MEMORY,
        secret_key="test-rotation-lifecycle-secret",
    )
    db = DatabaseManager(settings)
    await db.init()
    await db.create_all()
    yield db, settings
    await db.close_all()


@pytest.fixture
async def km(km_db):
    db, _ = km_db
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()
    return km


@pytest.fixture
def lifecycle(km):
    return KeyRotationLifecycle(km, redis=None)


# ── initiate_rotation ──


async def test_initiate_rotation_creates_pending_key(lifecycle, km):
    """initiate_rotation should create a new key with PENDING status."""
    result = await lifecycle.initiate_rotation()
    assert result["status"] == "initiated"
    assert "pending_kid" in result

    db = km.db
    async with db.get_session("identity") as session:
        res = await session.execute(
            select(JWKSKey).where(JWKSKey.status == PENDING)
        )
        pending_keys = res.scalars().all()

    assert len(pending_keys) == 1
    assert pending_keys[0].kid == result["pending_kid"]


async def test_pending_key_in_verification_keys(lifecycle, km):
    """PENDING key should appear in verification keys (for pre-caching)."""
    result = await lifecycle.initiate_rotation()
    pending_kid = result["pending_kid"]

    verification_keys = await km.get_verification_keys()
    assert pending_kid in verification_keys


async def test_pending_key_not_used_for_signing(lifecycle, km):
    """PENDING key should NOT be returned by get_signing_key()."""
    await lifecycle.initiate_rotation()

    # get_signing_key should still return the ACTIVE key, not the PENDING one
    _, signing_kid = await km.get_signing_key()

    db = km.db
    async with db.get_session("identity") as session:
        res = await session.execute(
            select(JWKSKey).where(JWKSKey.kid == signing_kid)
        )
        key = res.scalar_one()

    assert key.status == ACTIVE


async def test_duplicate_initiate_returns_already_pending(lifecycle):
    """Calling initiate twice should return 'already_pending' status."""
    first = await lifecycle.initiate_rotation()
    assert first["status"] == "initiated"

    second = await lifecycle.initiate_rotation()
    assert second["status"] == "already_pending"
    assert second["pending_kid"] == first["pending_kid"]


# ── activate_new_key ──


async def test_activate_promotes_pending_to_active(lifecycle, km):
    """activate_new_key should promote PENDING→ACTIVE and ACTIVE→RETIRING."""
    _, old_kid = await km.get_signing_key()

    init_result = await lifecycle.initiate_rotation()
    pending_kid = init_result["pending_kid"]

    activate_result = await lifecycle.activate_new_key(pending_kid)
    assert activate_result["status"] == "activated"
    assert activate_result["active_kid"] == pending_kid

    db = km.db
    async with db.get_session("identity") as session:
        # New key should be ACTIVE
        res = await session.execute(
            select(JWKSKey).where(JWKSKey.kid == pending_kid)
        )
        assert res.scalar_one().status == ACTIVE

        # Old key should be RETIRING
        res = await session.execute(
            select(JWKSKey).where(JWKSKey.kid == old_kid)
        )
        assert res.scalar_one().status == RETIRING


async def test_retiring_key_still_validates(lifecycle, km):
    """After activation, RETIRING key should still be in verification keys."""
    _, old_kid = await km.get_signing_key()

    init_result = await lifecycle.initiate_rotation()
    pending_kid = init_result["pending_kid"]

    await lifecycle.activate_new_key(pending_kid)

    verification_keys = await km.get_verification_keys()
    assert old_kid in verification_keys
    assert pending_kid in verification_keys


async def test_cannot_activate_non_pending_key(lifecycle):
    """Activating a kid that's not PENDING should return error."""
    result = await lifecycle.activate_new_key("nonexistent")
    assert result["status"] == "error"
    assert "No PENDING key" in result["message"]


# ── retire_old_key ──


async def test_retire_moves_retiring_to_retired(lifecycle, km):
    """retire_old_key should move RETIRING→RETIRED."""
    _, old_kid = await km.get_signing_key()

    init_result = await lifecycle.initiate_rotation()
    pending_kid = init_result["pending_kid"]

    await lifecycle.activate_new_key(pending_kid)
    retire_result = await lifecycle.retire_old_key(old_kid)

    assert retire_result["status"] == "retired"
    assert retire_result["retired_kid"] == old_kid

    db = km.db
    async with db.get_session("identity") as session:
        res = await session.execute(
            select(JWKSKey).where(JWKSKey.kid == old_kid)
        )
        assert res.scalar_one().status == RETIRED


async def test_retired_key_not_in_verification_keys(lifecycle, km):
    """RETIRED key should NOT appear in verification keys."""
    _, old_kid = await km.get_signing_key()

    init_result = await lifecycle.initiate_rotation()
    pending_kid = init_result["pending_kid"]

    await lifecycle.activate_new_key(pending_kid)
    await lifecycle.retire_old_key(old_kid)

    verification_keys = await km.get_verification_keys()
    assert old_kid not in verification_keys


async def test_cannot_retire_non_retiring_key(lifecycle):
    """Retiring a kid that's not RETIRING should return error."""
    result = await lifecycle.retire_old_key("nonexistent")
    assert result["status"] == "error"
    assert "No RETIRING key" in result["message"]


# ── Full lifecycle ──


async def test_full_lifecycle(lifecycle, km):
    """Full lifecycle: initiate → activate → retire."""
    _, original_kid = await km.get_signing_key()

    # Step 1: Initiate
    init = await lifecycle.initiate_rotation()
    assert init["status"] == "initiated"
    new_kid = init["pending_kid"]

    # Step 2: Activate
    activate = await lifecycle.activate_new_key(new_kid)
    assert activate["status"] == "activated"

    # Signing key should now be the new one
    _, signing_kid = await km.get_signing_key()
    assert signing_kid == new_kid

    # Step 3: Retire
    retire = await lifecycle.retire_old_key(original_kid)
    assert retire["status"] == "retired"

    # Only the new key should be in verification keys
    verification_keys = await km.get_verification_keys()
    assert new_kid in verification_keys
    assert original_kid not in verification_keys


# ── Rotation status ──


async def test_rotation_status_stable(lifecycle):
    """Status should be 'stable' when no rotation is in progress."""
    status = await lifecycle.get_rotation_status()
    assert status["rotation_phase"] == "stable"
    assert len(status["keys"]) == 1
    assert status["keys"][0]["status"] == ACTIVE


async def test_rotation_status_pre_announcement(lifecycle):
    """Status should be 'pre-announcement' when a PENDING key exists."""
    await lifecycle.initiate_rotation()
    status = await lifecycle.get_rotation_status()
    assert status["rotation_phase"] == "pre-announcement"
    assert len(status["keys"]) == 2


async def test_rotation_status_overlap(lifecycle):
    """Status should be 'overlap' when a RETIRING key exists."""
    init = await lifecycle.initiate_rotation()
    await lifecycle.activate_new_key(init["pending_kid"])

    status = await lifecycle.get_rotation_status()
    assert status["rotation_phase"] == "overlap"
    assert len(status["keys"]) == 2
