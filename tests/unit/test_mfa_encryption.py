"""Unit tests for MFA TOTP secret encryption at rest."""

import json

import pytest
from sqlalchemy import select

from zuultimate.identity.mfa_service import MFAService
from zuultimate.identity.models import MFADevice
from zuultimate.identity.service import IdentityService


@pytest.fixture
def mfa_svc(test_db, test_settings):
    return MFAService(test_db, test_settings)


@pytest.fixture
def id_svc(test_db, test_settings):
    return IdentityService(test_db, test_settings)


async def _create_user(id_svc, username="mfauser"):
    return await id_svc.register(
        email=f"{username}@test.com",
        username=username,
        password="password123",
    )


def test_encrypt_decrypt_roundtrip(mfa_svc):
    """Encrypt then decrypt should return original secret."""
    secret = "JBSWY3DPEHPK3PXP"
    encrypted = mfa_svc._encrypt_secret(secret)
    decrypted = mfa_svc._decrypt_secret(encrypted)
    assert decrypted == secret


def test_encrypted_secret_is_json(mfa_svc):
    """Encrypted output should be JSON with ct, nonce, tag."""
    encrypted = mfa_svc._encrypt_secret("TESTSECRET")
    envelope = json.loads(encrypted)
    assert "ct" in envelope
    assert "nonce" in envelope
    assert "tag" in envelope


def test_encrypted_secret_not_plaintext(mfa_svc):
    """The encrypted value should not contain the plaintext."""
    secret = "JBSWY3DPEHPK3PXP"
    encrypted = mfa_svc._encrypt_secret(secret)
    assert secret not in encrypted


def test_backwards_compat_plaintext(mfa_svc):
    """Old unencrypted secrets should still be decryptable."""
    plain_secret = "OLDPLAINTEXTSECRET"
    result = mfa_svc._decrypt_secret(plain_secret)
    assert result == plain_secret


async def test_stored_secret_encrypted_in_db(mfa_svc, id_svc, test_db):
    """After setup, the DB should contain encrypted (not plaintext) secret."""
    user = await _create_user(id_svc)
    result = await mfa_svc.setup_totp(user["id"])
    raw_secret = result["secret"]

    # Read from DB directly
    async with test_db.get_session("identity") as session:
        db_result = await session.execute(
            select(MFADevice).where(MFADevice.user_id == user["id"])
        )
        device = db_result.scalar_one()

    # DB value should be JSON envelope, not plaintext
    assert device.secret_encrypted != raw_secret
    envelope = json.loads(device.secret_encrypted)
    assert "ct" in envelope

    # Decryption should recover original
    decrypted = mfa_svc._decrypt_secret(device.secret_encrypted)
    assert decrypted == raw_secret
