"""Unit tests for email verification flow."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.models import EmailVerificationToken
from zuultimate.identity.service import IdentityService


@pytest.fixture
def svc(test_db, test_settings):
    return IdentityService(test_db, test_settings)


async def _register(svc, username="verifyuser"):
    return await svc.register(
        email=f"{username}@test.com",
        username=username,
        password="password123",
    )


async def test_create_verification_token(svc):
    user = await _register(svc)
    result = await svc.create_verification_token(user["id"])
    assert result["user_id"] == user["id"]
    assert result["email"] == user["email"]
    assert len(result["token"]) == 64  # 32 bytes hex
    assert result["expires_at"] is not None


async def test_verify_email_success(svc):
    user = await _register(svc)
    token_result = await svc.create_verification_token(user["id"])
    result = await svc.verify_email(token_result["token"])
    assert result["verified"] is True
    assert result["user_id"] == user["id"]

    # User should now be verified
    user_data = await svc.get_user(user["id"])
    assert user_data["is_verified"] is True


async def test_verify_email_invalid_token(svc):
    with pytest.raises(ValidationError, match="Invalid"):
        await svc.verify_email("bogus-token")


async def test_verify_email_already_verified(svc):
    user = await _register(svc, "verifyuser2")
    token_result = await svc.create_verification_token(user["id"])
    await svc.verify_email(token_result["token"])

    # Trying to create another token should fail
    with pytest.raises(ValidationError, match="already verified"):
        await svc.create_verification_token(user["id"])


async def test_verify_email_token_reuse_rejected(svc):
    user = await _register(svc, "verifyuser3")
    token_result = await svc.create_verification_token(user["id"])
    await svc.verify_email(token_result["token"])

    # Reusing the same token fails
    with pytest.raises(ValidationError, match="Invalid"):
        await svc.verify_email(token_result["token"])


async def test_create_token_invalidates_previous(svc, test_db):
    user = await _register(svc, "verifyuser4")
    first = await svc.create_verification_token(user["id"])
    second = await svc.create_verification_token(user["id"])

    # First token should be invalidated
    with pytest.raises(ValidationError, match="Invalid"):
        await svc.verify_email(first["token"])

    # Second token should work
    result = await svc.verify_email(second["token"])
    assert result["verified"] is True


async def test_create_token_nonexistent_user(svc):
    with pytest.raises(NotFoundError):
        await svc.create_verification_token("nonexistent")


async def test_expired_token_rejected(svc, test_db):
    user = await _register(svc, "verifyuser5")
    token_result = await svc.create_verification_token(user["id"])

    # Manually expire the token in DB
    token_hash = hashlib.sha256(token_result["token"].encode()).hexdigest()
    async with test_db.get_session("identity") as session:
        result = await session.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token_hash == token_hash
            )
        )
        record = result.scalar_one()
        record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    with pytest.raises(ValidationError, match="expired"):
        await svc.verify_email(token_result["token"])
