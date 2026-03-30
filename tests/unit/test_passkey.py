"""Unit tests for passkey (FIDO2/WebAuthn) registration and authentication."""

import pytest
from unittest.mock import MagicMock, patch

from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.identity.models import User, WebAuthnCredential
from zuultimate.identity.passkey_service import PasskeyService


@pytest.fixture
def svc(test_db, test_settings):
    return PasskeyService(test_db, test_settings)


@pytest.fixture(autouse=True)
def _clear_pending_challenges():
    """Clear pending challenges between tests to prevent cross-contamination."""
    PasskeyService._pending_challenges.clear()
    yield
    PasskeyService._pending_challenges.clear()


@pytest.fixture
async def test_user(test_db):
    """Create a test user in the identity database."""
    async with test_db.get_session("identity") as session:
        user = User(
            email="passkey@test.com",
            username="passkeyuser",
            display_name="Passkey User",
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()
        user_id = user.id
    return user_id


def _mock_registration_verification():
    """Build a mock return value for verify_registration_response."""
    mock = MagicMock()
    mock.credential_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    mock.credential_public_key = b"\x10\x20\x30\x40\x50\x60\x70\x80"
    mock.sign_count = 0
    mock.aaguid = "00000000-0000-0000-0000-000000000000"
    return mock


def _mock_authentication_verification(new_sign_count: int = 1):
    """Build a mock return value for verify_authentication_response."""
    mock = MagicMock()
    mock.new_sign_count = new_sign_count
    mock.credential_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    return mock


# ------------------------------------------------------------------
# Registration tests
# ------------------------------------------------------------------


@patch("zuultimate.identity.passkey_service.generate_registration_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_begin_registration_returns_options(
    mock_options_json, mock_gen_opts, svc, test_user,
):
    """Verify begin_registration returns options dict and challenge."""
    mock_opts = MagicMock()
    mock_opts.challenge = b"\xde\xad\xbe\xef"
    mock_gen_opts.return_value = mock_opts
    mock_options_json.return_value = '{"rp": {"id": "localhost"}, "challenge": "3q2-7w"}'

    result = await svc.begin_registration(test_user)

    assert "options" in result
    assert "challenge" in result
    assert isinstance(result["options"], dict)
    assert result["options"]["rp"]["id"] == "localhost"
    mock_gen_opts.assert_called_once()


@patch("zuultimate.identity.passkey_service.verify_registration_response")
@patch("zuultimate.identity.passkey_service.parse_registration_credential_json")
@patch("zuultimate.identity.passkey_service.generate_registration_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_complete_registration_stores_credential(
    mock_options_json, mock_gen_opts, mock_parse_reg, mock_verify, svc, test_user, test_db,
):
    """Verify complete_registration stores credential in DB after successful verification."""
    # Begin registration first to get a valid challenge
    mock_opts = MagicMock()
    mock_opts.challenge = b"\xde\xad\xbe\xef"
    mock_gen_opts.return_value = mock_opts
    mock_options_json.return_value = '{"rp": {"id": "localhost"}}'

    begin_result = await svc.begin_registration(test_user)
    challenge_id = begin_result["challenge"]

    # Mock parse and verification
    mock_parse_reg.return_value = MagicMock()
    mock_verify.return_value = _mock_registration_verification()

    fake_credential = {
        "id": "AQIDBAUGB-g",
        "rawId": "AQIDBAUGBwg",
        "type": "public-key",
        "response": {
            "attestationObject": "o2NmbXRkbm9uZQ",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
        },
    }

    result = await svc.complete_registration(
        user_id=test_user,
        credential_response=fake_credential,
        challenge=challenge_id,
    )

    assert "credential_db_id" in result
    assert "credential_id" in result

    # Verify credential is in DB
    from sqlalchemy import select

    async with test_db.get_session("identity") as session:
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == test_user,
        )
        db_result = await session.execute(stmt)
        cred = db_result.scalar_one_or_none()
        assert cred is not None
        assert cred.is_active is True


@patch("zuultimate.identity.passkey_service.verify_registration_response")
@patch("zuultimate.identity.passkey_service.parse_registration_credential_json")
@patch("zuultimate.identity.passkey_service.generate_registration_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_duplicate_credential_rejection(
    mock_options_json, mock_gen_opts, mock_parse_reg, mock_verify, svc, test_user,
):
    """Verify registering the same credential_id twice raises ValidationError."""
    mock_opts = MagicMock()
    mock_opts.challenge = b"\xde\xad\xbe\xef"
    mock_gen_opts.return_value = mock_opts
    mock_options_json.return_value = '{"rp": {"id": "localhost"}}'
    mock_parse_reg.return_value = MagicMock()

    # First registration
    begin1 = await svc.begin_registration(test_user)
    mock_verify.return_value = _mock_registration_verification()

    await svc.complete_registration(
        user_id=test_user,
        credential_response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
        challenge=begin1["challenge"],
    )

    # Second registration with same credential_id
    begin2 = await svc.begin_registration(test_user)
    mock_verify.return_value = _mock_registration_verification()  # same credential_id bytes

    with pytest.raises(ValidationError, match="already registered"):
        await svc.complete_registration(
            user_id=test_user,
            credential_response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
            challenge=begin2["challenge"],
        )


# ------------------------------------------------------------------
# Authentication tests
# ------------------------------------------------------------------


@patch("zuultimate.identity.passkey_service.generate_authentication_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_begin_authentication_returns_options(
    mock_options_json, mock_gen_opts, svc,
):
    """Verify begin_authentication returns options with challenge."""
    mock_opts = MagicMock()
    mock_opts.challenge = b"\xca\xfe\xba\xbe"
    mock_gen_opts.return_value = mock_opts
    mock_options_json.return_value = '{"rpId": "localhost", "challenge": "yv66vg"}'

    result = await svc.begin_authentication()

    assert "options" in result
    assert "challenge" in result
    assert isinstance(result["options"], dict)
    mock_gen_opts.assert_called_once()


@patch("zuultimate.identity.passkey_service.verify_authentication_response")
@patch("zuultimate.identity.passkey_service.parse_authentication_credential_json")
@patch("zuultimate.identity.passkey_service.verify_registration_response")
@patch("zuultimate.identity.passkey_service.parse_registration_credential_json")
@patch("zuultimate.identity.passkey_service.generate_authentication_options")
@patch("zuultimate.identity.passkey_service.generate_registration_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_complete_authentication_issues_tokens(
    mock_options_json, mock_gen_reg, mock_gen_auth,
    mock_parse_reg, mock_verify_reg,
    mock_parse_auth, mock_verify_auth,
    svc, test_user,
):
    """Verify complete_authentication returns access and refresh tokens."""
    # First register a credential
    mock_opts_reg = MagicMock()
    mock_opts_reg.challenge = b"\xde\xad\xbe\xef"
    mock_gen_reg.return_value = mock_opts_reg
    mock_options_json.return_value = '{"rp": {"id": "localhost"}}'
    mock_parse_reg.return_value = MagicMock()

    begin_reg = await svc.begin_registration(test_user)
    mock_verify_reg.return_value = _mock_registration_verification()

    await svc.complete_registration(
        user_id=test_user,
        credential_response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
        challenge=begin_reg["challenge"],
    )

    # Now authenticate
    mock_opts_auth = MagicMock()
    mock_opts_auth.challenge = b"\xca\xfe\xba\xbe"
    mock_gen_auth.return_value = mock_opts_auth
    mock_options_json.return_value = '{"rpId": "localhost"}'

    begin_auth = await svc.begin_authentication(user_id=test_user)

    mock_verify_auth.return_value = _mock_authentication_verification(new_sign_count=1)

    # Build a mock credential with raw_id matching the registered credential
    mock_auth_cred = MagicMock()
    mock_auth_cred.raw_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    mock_parse_auth.return_value = mock_auth_cred

    result = await svc.complete_authentication(
        credential_response={"id": "x", "rawId": "AQIDBAUGBwg", "type": "public-key", "response": {}},
        challenge=begin_auth["challenge"],
    )

    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "bearer"
    assert result["user_id"] == test_user


@patch("zuultimate.identity.passkey_service.verify_authentication_response")
@patch("zuultimate.identity.passkey_service.parse_authentication_credential_json")
@patch("zuultimate.identity.passkey_service.verify_registration_response")
@patch("zuultimate.identity.passkey_service.parse_registration_credential_json")
@patch("zuultimate.identity.passkey_service.generate_authentication_options")
@patch("zuultimate.identity.passkey_service.generate_registration_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_sign_count_replay_rejection(
    mock_options_json, mock_gen_reg, mock_gen_auth,
    mock_parse_reg, mock_verify_reg,
    mock_parse_auth, mock_verify_auth,
    svc, test_user,
):
    """Verify authentication rejects sign_count that is not greater than stored."""
    # Register credential with sign_count=5
    mock_opts_reg = MagicMock()
    mock_opts_reg.challenge = b"\xde\xad\xbe\xef"
    mock_gen_reg.return_value = mock_opts_reg
    mock_options_json.return_value = '{"rp": {"id": "localhost"}}'
    mock_parse_reg.return_value = MagicMock()

    begin_reg = await svc.begin_registration(test_user)
    reg_verification = _mock_registration_verification()
    reg_verification.sign_count = 5
    mock_verify_reg.return_value = reg_verification

    await svc.complete_registration(
        user_id=test_user,
        credential_response={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
        challenge=begin_reg["challenge"],
    )

    # Attempt authentication with sign_count=3 (less than stored 5) -- should fail
    mock_opts_auth = MagicMock()
    mock_opts_auth.challenge = b"\xca\xfe\xba\xbe"
    mock_gen_auth.return_value = mock_opts_auth
    mock_options_json.return_value = '{"rpId": "localhost"}'

    begin_auth = await svc.begin_authentication(user_id=test_user)

    # verify_authentication_response succeeds but sign_count is too low
    mock_verify_auth.return_value = _mock_authentication_verification(new_sign_count=3)

    mock_auth_cred = MagicMock()
    mock_auth_cred.raw_id = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    mock_parse_auth.return_value = mock_auth_cred

    with pytest.raises(AuthenticationError, match="replay"):
        await svc.complete_authentication(
            credential_response={"id": "x", "rawId": "AQIDBAUGBwg", "type": "public-key", "response": {}},
            challenge=begin_auth["challenge"],
        )


@patch("zuultimate.identity.passkey_service.parse_authentication_credential_json")
@patch("zuultimate.identity.passkey_service.generate_authentication_options")
@patch("zuultimate.identity.passkey_service.options_to_json")
async def test_unknown_credential_rejection(
    mock_options_json, mock_gen_auth, mock_parse_auth, svc,
):
    """Verify authentication with unknown credential_id raises AuthenticationError."""
    mock_opts = MagicMock()
    mock_opts.challenge = b"\xca\xfe\xba\xbe"
    mock_gen_auth.return_value = mock_opts
    mock_options_json.return_value = '{"rpId": "localhost"}'

    begin_auth = await svc.begin_authentication()

    mock_auth_cred = MagicMock()
    mock_auth_cred.raw_id = b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"  # not registered
    mock_parse_auth.return_value = mock_auth_cred

    with pytest.raises(AuthenticationError, match="Unknown credential"):
        await svc.complete_authentication(
            credential_response={"id": "x", "rawId": "xxx", "type": "public-key", "response": {}},
            challenge=begin_auth["challenge"],
        )
