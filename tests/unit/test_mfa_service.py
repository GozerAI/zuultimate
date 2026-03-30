"""Unit tests for TOTP MFA service."""

import pyotp
import pytest

from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.identity.mfa_service import MFAService
from zuultimate.identity.service import IdentityService


@pytest.fixture
async def services(test_db, test_settings):
    identity_svc = IdentityService(test_db, test_settings)
    mfa_svc = MFAService(test_db, test_settings)
    user = await identity_svc.register("mfa@test.com", "mfauser", "password123")
    return {"mfa": mfa_svc, "identity": identity_svc, "user_id": user["id"]}


async def test_setup_totp_returns_secret(services):
    result = await services["mfa"].setup_totp(services["user_id"])
    assert "secret" in result
    assert "provisioning_uri" in result
    assert "device_id" in result
    assert "otpauth://" in result["provisioning_uri"]


async def test_setup_duplicate_totp_fails(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    # Verify to activate
    totp = pyotp.TOTP(setup["secret"])
    await services["mfa"].verify_totp(services["user_id"], totp.now())
    # Attempting second setup should fail
    with pytest.raises(ValidationError, match="already configured"):
        await services["mfa"].setup_totp(services["user_id"])


async def test_verify_totp_activates_device(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    totp = pyotp.TOTP(setup["secret"])
    result = await services["mfa"].verify_totp(services["user_id"], totp.now())
    assert result["status"] == "mfa_enabled"


async def test_verify_wrong_code_fails(services):
    await services["mfa"].setup_totp(services["user_id"])
    with pytest.raises(AuthenticationError, match="Invalid TOTP"):
        await services["mfa"].verify_totp(services["user_id"], "000000")


async def test_verify_no_pending_device_fails(services):
    with pytest.raises(NotFoundError, match="No pending"):
        await services["mfa"].verify_totp(services["user_id"], "123456")


async def test_has_active_mfa_false_by_default(services):
    assert await services["mfa"].has_active_mfa(services["user_id"]) is False


async def test_has_active_mfa_true_after_verify(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    totp = pyotp.TOTP(setup["secret"])
    await services["mfa"].verify_totp(services["user_id"], totp.now())
    assert await services["mfa"].has_active_mfa(services["user_id"]) is True


async def test_complete_challenge_success(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    totp = pyotp.TOTP(setup["secret"])
    await services["mfa"].verify_totp(services["user_id"], totp.now())

    mfa_token = services["mfa"].create_mfa_token(services["user_id"], "mfauser")
    result = await services["mfa"].complete_challenge(mfa_token, totp.now())
    assert result["user_id"] == services["user_id"]


async def test_complete_challenge_wrong_code_fails(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    totp = pyotp.TOTP(setup["secret"])
    await services["mfa"].verify_totp(services["user_id"], totp.now())

    mfa_token = services["mfa"].create_mfa_token(services["user_id"], "mfauser")
    with pytest.raises(AuthenticationError, match="Invalid TOTP"):
        await services["mfa"].complete_challenge(mfa_token, "000000")


async def test_complete_challenge_invalid_token_fails(services):
    with pytest.raises(AuthenticationError, match="Invalid or expired"):
        await services["mfa"].complete_challenge("bad-token", "123456")


async def test_login_returns_mfa_required_when_enabled(services):
    setup = await services["mfa"].setup_totp(services["user_id"])
    totp = pyotp.TOTP(setup["secret"])
    await services["mfa"].verify_totp(services["user_id"], totp.now())

    login_result = await services["identity"].login("mfauser", "password123")
    assert login_result["mfa_required"] is True
    assert "mfa_token" in login_result
