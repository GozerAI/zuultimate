"""Unit tests for CrossServiceBindingService (Phase F.2)."""

from datetime import datetime, timedelta, timezone

import pytest

from zuultimate.common.exceptions import NotFoundError
from zuultimate.vault.cross_service import CrossServiceBinding, CrossServiceBindingService


async def _noop_sleep(delay):
    """Instant sleep replacement for tests."""
    pass


@pytest.fixture
def svc(test_db, test_settings):
    return CrossServiceBindingService(test_db, test_settings, sleep_func=_noop_sleep)


# ---------------------------------------------------------------------------
# bind + verify
# ---------------------------------------------------------------------------


async def test_bind_returns_id(svc):
    binding_id = await svc.bind("vinzy-sig-1", "bp_token_1")
    assert isinstance(binding_id, str)
    assert len(binding_id) == 36  # UUID


async def test_verify_correct_pair(svc):
    await svc.bind("vinzy-sig-2", "bp_token_2")
    assert await svc.verify_binding("vinzy-sig-2", "bp_token_2") is True


async def test_verify_wrong_vinzy_sig(svc):
    await svc.bind("vinzy-sig-3", "bp_token_3")
    assert await svc.verify_binding("wrong-sig", "bp_token_3") is False


async def test_verify_wrong_pass_token(svc):
    await svc.bind("vinzy-sig-4", "bp_token_4")
    assert await svc.verify_binding("vinzy-sig-4", "wrong-token") is False


async def test_verify_no_bindings(svc):
    assert await svc.verify_binding("nonexistent", "also-nonexistent") is False


# ---------------------------------------------------------------------------
# revocation with salt erasure
# ---------------------------------------------------------------------------


async def test_revoke_binding(svc):
    binding_id = await svc.bind("vinzy-sig-5", "bp_token_5")
    result = await svc.revoke_binding(binding_id)
    assert result["revoked"] is True
    assert result["binding_id"] == binding_id


async def test_revoked_binding_verify_fails(svc):
    binding_id = await svc.bind("vinzy-sig-6", "bp_token_6")
    await svc.revoke_binding(binding_id)
    assert await svc.verify_binding("vinzy-sig-6", "bp_token_6") is False


async def test_revoke_nonexistent_raises(svc):
    with pytest.raises(NotFoundError, match="not found"):
        await svc.revoke_binding("nonexistent-id")


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------


async def test_expired_binding_verify_fails(svc):
    binding_id = await svc.bind("vinzy-sig-7", "bp_token_7", ttl_seconds=1)

    # Manually expire the binding
    from sqlalchemy import select

    async with svc.db.get_session("credential") as session:
        result = await session.execute(
            select(CrossServiceBinding).where(CrossServiceBinding.id == binding_id)
        )
        binding = result.scalar_one()
        binding.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    assert await svc.verify_binding("vinzy-sig-7", "bp_token_7") is False


# ---------------------------------------------------------------------------
# multiple bindings
# ---------------------------------------------------------------------------


async def test_multiple_bindings_independent(svc):
    await svc.bind("vinzy-sig-a", "bp_token_a")
    await svc.bind("vinzy-sig-b", "bp_token_b")

    assert await svc.verify_binding("vinzy-sig-a", "bp_token_a") is True
    assert await svc.verify_binding("vinzy-sig-b", "bp_token_b") is True
    # Cross-pair should not verify
    assert await svc.verify_binding("vinzy-sig-a", "bp_token_b") is False


async def test_binding_purpose_and_sovereignty(svc):
    binding_id = await svc.bind(
        "vinzy-sig-meta", "bp_token_meta",
        purpose="audit", sovereignty_ring="eu",
    )
    from sqlalchemy import select

    async with svc.db.get_session("credential") as session:
        result = await session.execute(
            select(CrossServiceBinding).where(CrossServiceBinding.id == binding_id)
        )
        binding = result.scalar_one()
    assert binding.purpose == "audit"
    assert binding.sovereignty_ring == "eu"
