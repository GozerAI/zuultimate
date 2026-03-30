"""Unit tests for BlindPassService (Phase F.1)."""

import os
from datetime import datetime, timedelta, timezone

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.vault.blind_pass import BlindPassService


@pytest.fixture
def svc(test_db, test_settings):
    return BlindPassService(test_db, test_settings)


@pytest.fixture
def client_shard():
    return os.urandom(32)


# ---------------------------------------------------------------------------
# create + verify
# ---------------------------------------------------------------------------


async def test_create_returns_token(svc, client_shard):
    result = await svc.create_blind_pass(
        subject_id="user-123",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    assert result["token"].startswith("bp_")
    assert result["purpose"] == "provisioning"
    assert result["sovereignty_ring"] == "us"
    assert "expires_at" in result


async def test_verify_valid_token(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-123",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    result = await svc.verify_blind_pass(created["token"], "provisioning")
    assert result["valid"] is True
    assert result["purpose"] == "provisioning"


async def test_verify_wrong_purpose(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-123",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    result = await svc.verify_blind_pass(created["token"], "admin-override")
    assert result["valid"] is False
    assert result["reason"] == "Purpose mismatch"


async def test_verify_nonexistent_token(svc):
    result = await svc.verify_blind_pass("bp_nonexistent", "provisioning")
    assert result["valid"] is False
    assert result["reason"] == "Token not found"


# ---------------------------------------------------------------------------
# resolve with both shards
# ---------------------------------------------------------------------------


async def test_resolve_with_correct_shard(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-456",
        tenant_id="tenant-xyz",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    resolved = await svc.resolve_blind_pass(created["token"], client_shard)
    assert resolved == "user-456"


async def test_resolve_with_wrong_shard(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-456",
        tenant_id="tenant-xyz",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    wrong_shard = os.urandom(32)
    with pytest.raises(ValidationError, match="wrong key shard"):
        await svc.resolve_blind_pass(created["token"], wrong_shard)


async def test_resolve_invalid_shard_length(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-456",
        tenant_id="tenant-xyz",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    with pytest.raises(ValidationError, match="32 bytes"):
        await svc.resolve_blind_pass(created["token"], b"short")


async def test_resolve_nonexistent_token(svc, client_shard):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.resolve_blind_pass("bp_nonexistent", client_shard)


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------


async def test_expired_token_verify_fails(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-789",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=1,
        client_key_shard=client_shard,
    )
    # Manually expire by updating the record
    from zuultimate.vault.blind_pass import BlindPassToken
    import hashlib
    from sqlalchemy import select

    token_hash = hashlib.sha256(created["token"].encode()).hexdigest()
    async with svc.db.get_session("credential") as session:
        result = await session.execute(
            select(BlindPassToken).where(BlindPassToken.token_hash == token_hash)
        )
        record = result.scalar_one()
        record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    result = await svc.verify_blind_pass(created["token"], "provisioning")
    assert result["valid"] is False
    assert result["reason"] == "Token expired"


async def test_expired_token_resolve_fails(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-789",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=1,
        client_key_shard=client_shard,
    )
    from zuultimate.vault.blind_pass import BlindPassToken
    import hashlib
    from sqlalchemy import select

    token_hash = hashlib.sha256(created["token"].encode()).hexdigest()
    async with svc.db.get_session("credential") as session:
        result = await session.execute(
            select(BlindPassToken).where(BlindPassToken.token_hash == token_hash)
        )
        record = result.scalar_one()
        record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    with pytest.raises(ValidationError, match="expired"):
        await svc.resolve_blind_pass(created["token"], client_shard)


# ---------------------------------------------------------------------------
# revocation
# ---------------------------------------------------------------------------


async def test_revoke_token(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-revoke",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    result = await svc.revoke_blind_pass(created["token"])
    assert result["revoked"] is True


async def test_revoked_token_verify_fails(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-revoke",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    await svc.revoke_blind_pass(created["token"])
    result = await svc.verify_blind_pass(created["token"], "provisioning")
    assert result["valid"] is False
    assert result["reason"] == "Token revoked"


async def test_revoked_token_resolve_fails(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-revoke",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
    )
    await svc.revoke_blind_pass(created["token"])
    with pytest.raises(ValidationError, match="revoked"):
        await svc.resolve_blind_pass(created["token"], client_shard)


async def test_revoke_nonexistent_raises(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.revoke_blind_pass("bp_nonexistent")


# ---------------------------------------------------------------------------
# create validation
# ---------------------------------------------------------------------------


async def test_create_invalid_shard_length(svc):
    with pytest.raises(ValidationError, match="32 bytes"):
        await svc.create_blind_pass(
            subject_id="user-123",
            tenant_id="tenant-abc",
            purpose="provisioning",
            ttl_seconds=3600,
            client_key_shard=b"short",
        )


async def test_sovereignty_ring_propagated(svc, client_shard):
    created = await svc.create_blind_pass(
        subject_id="user-eu",
        tenant_id="tenant-eu",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=client_shard,
        sovereignty_ring="eu",
    )
    assert created["sovereignty_ring"] == "eu"
    result = await svc.verify_blind_pass(created["token"], "provisioning")
    assert result["sovereignty_ring"] == "eu"


async def test_different_shards_different_tokens(svc):
    shard_a = os.urandom(32)
    shard_b = os.urandom(32)
    a = await svc.create_blind_pass(
        subject_id="user-123",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=shard_a,
    )
    b = await svc.create_blind_pass(
        subject_id="user-123",
        tenant_id="tenant-abc",
        purpose="provisioning",
        ttl_seconds=3600,
        client_key_shard=shard_b,
    )
    assert a["token"] != b["token"]
