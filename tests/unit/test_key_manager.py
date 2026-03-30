"""Tests for RSA KeyManager + RS256 JWT signing."""

import pytest

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.key_manager import ACTIVE, RETIRED, RETIRING, JWKSKey, KeyManager
from zuultimate.common.security import create_jwt, decode_jwt

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
        secret_key="test-key-manager-secret",
    )
    db = DatabaseManager(settings)
    await db.init()
    await db.create_all()
    yield db, settings
    await db.close_all()


@pytest.fixture
async def km(km_db):
    db, settings = km_db
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()
    return km


async def test_bootstrap_creates_active_key(km_db):
    db, _ = km_db
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()

    from sqlalchemy import select

    async with db.get_session("identity") as session:
        result = await session.execute(select(JWKSKey).where(JWKSKey.status == ACTIVE))
        keys = result.scalars().all()
    assert len(keys) == 1
    assert keys[0].algorithm == "RS256"
    assert keys[0].region == "us"


async def test_bootstrap_idempotent(km_db):
    db, _ = km_db
    km = KeyManager(db, region="us")
    await km.ensure_key_exists()
    await km.ensure_key_exists()

    from sqlalchemy import select

    async with db.get_session("identity") as session:
        result = await session.execute(select(JWKSKey).where(JWKSKey.status == ACTIVE))
        assert len(result.scalars().all()) == 1


async def test_get_signing_key(km):
    pem, kid = await km.get_signing_key()
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert len(kid) == 8


async def test_get_verification_keys(km):
    keys = await km.get_verification_keys()
    assert len(keys) == 1
    for kid, pem in keys.items():
        assert len(kid) == 8
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")


async def test_rotation_lifecycle(km):
    # Get initial kid
    _, kid1 = await km.get_signing_key()

    # Rotate
    kid2 = await km.rotate()
    assert kid2 != kid1

    # New signing key should be kid2
    _, current_kid = await km.get_signing_key()
    assert current_kid == kid2

    # Verification keys should include both (kid1 RETIRING, kid2 ACTIVE)
    verification_keys = await km.get_verification_keys()
    assert kid1 in verification_keys
    assert kid2 in verification_keys


async def test_second_rotation_retires_old(km):
    _, kid1 = await km.get_signing_key()
    kid2 = await km.rotate()
    kid3 = await km.rotate()

    verification_keys = await km.get_verification_keys()
    # kid1 should be RETIRED (excluded)
    assert kid1 not in verification_keys
    # kid2 should be RETIRING (included)
    assert kid2 in verification_keys
    # kid3 should be ACTIVE (included)
    assert kid3 in verification_keys


async def test_rs256_create_and_decode(km):
    pem, kid = await km.get_signing_key()
    public_keys = await km.get_verification_keys()

    token = create_jwt(
        {"sub": "user123", "type": "access"},
        "unused-secret",
        private_key=pem,
        kid=kid,
    )

    payload = decode_jwt(token, "unused-secret", public_keys=public_keys)
    assert payload["sub"] == "user123"
    assert payload["type"] == "access"
    assert payload["iss"] == "zuultimate"


async def test_rs256_decode_after_rotation(km):
    """Token signed with old key should still validate after rotation."""
    pem, kid = await km.get_signing_key()
    token = create_jwt(
        {"sub": "user-old", "type": "access"},
        "unused",
        private_key=pem,
        kid=kid,
    )

    # Rotate
    await km.rotate()

    # Old token should still verify (old key is RETIRING, not RETIRED)
    public_keys = await km.get_verification_keys()
    payload = decode_jwt(token, "unused", public_keys=public_keys)
    assert payload["sub"] == "user-old"


async def test_retired_key_rejected(km):
    """Token signed with a RETIRED key should fail verification."""
    pem, kid = await km.get_signing_key()
    token = create_jwt(
        {"sub": "user-retired", "type": "access"},
        "unused",
        private_key=pem,
        kid=kid,
    )

    # Two rotations: ACTIVE → RETIRING → RETIRED
    await km.rotate()
    await km.rotate()

    public_keys = await km.get_verification_keys()
    with pytest.raises(Exception):
        decode_jwt(token, "unused", public_keys=public_keys)


async def test_hs256_fallback():
    """Without public_keys, decode_jwt falls back to HS256."""
    token = create_jwt(
        {"sub": "user-hs", "type": "access"},
        "my-secret",
    )
    payload = decode_jwt(token, "my-secret")
    assert payload["sub"] == "user-hs"


async def test_get_all_public_keys_jwks_format(km):
    jwks = await km.get_all_public_keys()
    assert len(jwks) == 1
    key = jwks[0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "n" in key
    assert "e" in key
    assert len(key["kid"]) == 8


async def test_cache_invalidation(km):
    # Warm cache
    keys1 = await km.get_verification_keys()
    _, kid1 = await km.get_signing_key()

    # Rotate invalidates cache
    kid2 = await km.rotate()
    keys2 = await km.get_verification_keys()
    _, kid_new = await km.get_signing_key()

    assert kid_new == kid2
    assert kid2 in keys2


async def test_region_tag(km_db):
    db, _ = km_db
    km = KeyManager(db, region="eu")
    await km.ensure_key_exists()

    from sqlalchemy import select

    async with db.get_session("identity") as session:
        result = await session.execute(select(JWKSKey).where(JWKSKey.region == "eu"))
        keys = result.scalars().all()
    assert len(keys) >= 1
