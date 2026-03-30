"""Unit tests for SSO service -- OIDC with PKCE and nonce validation."""

import base64
import pytest
from unittest.mock import AsyncMock, patch

import httpx

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.sso_service import SSOService

_FAKE_REQUEST = httpx.Request("POST", "https://test.com/token")


@pytest.fixture
def svc(test_db, test_settings):
    return SSOService(test_db, test_settings)


@pytest.fixture(autouse=True)
def _clear_pending_states():
    """Clears pending state between tests to prevent cross-contamination."""
    SSOService._pending_states.clear()
    yield
    SSOService._pending_states.clear()


async def test_create_oidc_provider(svc):
    result = await svc.create_provider(
        name="Google",
        protocol="oidc",
        issuer_url="https://accounts.google.com",
        client_id="client-123",
        client_secret="secret-456",
    )
    assert result["name"] == "Google"
    assert result["protocol"] == "oidc"
    assert result["client_id"] == "client-123"
    assert result["is_active"] is True
    assert "id" in result


async def test_create_provider_rejects_saml(svc):
    """Rejects SAML protocol since only OIDC is supported."""
    with pytest.raises(ValidationError, match="Protocol"):
        await svc.create_provider(
            name="Okta", protocol="saml", issuer_url="https://okta.example.com",
            client_id="entity-id",
        )


async def test_create_provider_rejects_invalid_protocol(svc):
    """Rejects unknown protocol strings."""
    with pytest.raises(ValidationError, match="Protocol"):
        await svc.create_provider(
            name="Bad", protocol="ldap", issuer_url="x", client_id="y"
        )


async def test_list_providers(svc):
    await svc.create_provider("P1", "oidc", "https://a.com", "c1")
    await svc.create_provider("P2", "oidc", "https://b.com", "c2")
    providers = await svc.list_providers()
    assert len(providers) == 2


async def test_list_providers_filter_tenant(svc):
    await svc.create_provider("P1", "oidc", "https://a.com", "c1", tenant_id="t1")
    await svc.create_provider("P2", "oidc", "https://b.com", "c2", tenant_id="t2")
    providers = await svc.list_providers(tenant_id="t1")
    assert len(providers) == 1
    assert providers[0]["name"] == "P1"


async def test_get_provider(svc):
    created = await svc.create_provider("Google", "oidc", "https://google.com", "c1")
    result = await svc.get_provider(created["id"])
    assert result["name"] == "Google"


async def test_get_provider_not_found(svc):
    with pytest.raises(NotFoundError):
        await svc.get_provider("nonexistent")


async def test_initiate_oidc_login_includes_pkce(svc):
    """Validates that initiate_login generates PKCE code_challenge and S256 method."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    result = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")
    assert "redirect_url" in result
    assert "accounts.google.com/authorize" in result["redirect_url"]
    assert "client_id=client-123" in result["redirect_url"]
    assert "code_challenge=" in result["redirect_url"]
    assert "code_challenge_method=S256" in result["redirect_url"]
    assert len(result["state"]) == 32


async def test_initiate_login_includes_nonce(svc):
    """Validates that initiate_login generates a nonce in the auth URL and response."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    result = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")
    assert "nonce" in result
    assert len(result["nonce"]) == 32
    assert f"nonce={result['nonce']}" in result["redirect_url"]


async def test_initiate_login_stores_pending_state(svc):
    """Validates that initiate_login stores state for callback validation."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    result = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")
    state = result["state"]
    assert state in SSOService._pending_states
    pending = SSOService._pending_states[state]
    assert pending["nonce"] == result["nonce"]
    assert pending["provider_id"] == provider["id"]
    assert "code_verifier" in pending


def _mock_token_response(email="sso-user@google.com", name="SSO User"):
    """Builds a mock OIDC token exchange response."""
    return httpx.Response(200, json={
        "access_token": "idp-access-token",
        "token_type": "Bearer",
        "email": email,
        "preferred_username": email.split("@")[0],
        "name": name,
    }, request=_FAKE_REQUEST)


async def test_handle_callback_creates_user(svc):
    """Validates that callback creates user and returns JWT tokens."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )
    # Initiate login to populate pending state
    login = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")

    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await svc.handle_callback(
            provider["id"], "authcode123", login["state"],
            nonce=login["nonce"],
        )
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["sso_provider"] == "Google"
    assert "user_id" in result


async def test_handle_callback_sends_code_verifier(svc):
    """Validates that callback sends the PKCE code_verifier to the token endpoint."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )
    login = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")

    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        await svc.handle_callback(
            provider["id"], "authcode123", login["state"],
            nonce=login["nonce"],
        )

        # Verify code_verifier was sent in the token exchange request
        call_kwargs = mock_client.post.call_args
        posted_data = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data")
        assert "code_verifier" in posted_data
        assert len(posted_data["code_verifier"]) > 0


async def test_handle_callback_rejects_bad_nonce(svc):
    """Rejects callback when nonce does not match the stored value."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )
    login = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")

    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="[Nn]once mismatch"):
            await svc.handle_callback(
                provider["id"], "authcode123", login["state"],
                nonce="wrong-nonce-value",
            )


async def test_handle_callback_idempotent_user(svc):
    """Validates that repeated callbacks for same email reuse the same user."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )

    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        # First callback (no pending state -- graceful degradation)
        r1 = await svc.handle_callback(provider["id"], "code1", "state1")
        r2 = await svc.handle_callback(provider["id"], "code2", "state2")
    assert r1["user_id"] == r2["user_id"]


async def test_handle_callback_token_exchange_failure(svc):
    """Raises ValidationError when the IdP rejects the token exchange."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    error_response = httpx.Response(
        400, json={"error": "invalid_grant"}, request=_FAKE_REQUEST,
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=error_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="token exchange failed"):
            await svc.handle_callback(provider["id"], "badcode", "state")


async def test_handle_callback_network_error(svc):
    """Raises ValidationError on network failures during token exchange."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="network error"):
            await svc.handle_callback(provider["id"], "code", "state")


async def test_handle_callback_missing_email(svc):
    """Raises ValidationError when IdP response lacks an email claim."""
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    response = httpx.Response(200, json={"access_token": "tok"}, request=_FAKE_REQUEST)
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="email"):
            await svc.handle_callback(provider["id"], "code", "state")


async def test_handle_callback_with_id_token(svc):
    """Validates user info extraction from JWT id_token."""
    import base64
    import json as _json
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        _json.dumps({"email": "jwt@google.com", "name": "JWT User", "sub": "12345"}).encode()
    ).rstrip(b"=").decode()
    fake_jwt = f"{header}.{payload}.fakesignature"

    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="s",
    )
    response = httpx.Response(200, json={"id_token": fake_jwt}, request=_FAKE_REQUEST)
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await svc.handle_callback(provider["id"], "code", "state")
    assert result["user_id"]
    assert result["sso_provider"] == "Google"


def test_extract_user_info_from_top_level():
    """Validates _extract_user_info works with top-level fields."""
    email, username, name = SSOService._extract_user_info({
        "email": "a@b.com",
        "preferred_username": "auser",
        "name": "A B",
    })
    assert email == "a@b.com"
    assert username == "auser"
    assert name == "A B"


def test_extract_user_info_empty():
    """Returns empty strings when no claims are present."""
    email, username, name = SSOService._extract_user_info({})
    assert email == ""
    assert username == ""
    assert name == ""


async def test_deactivate_provider(svc):
    provider = await svc.create_provider("Tmp", "oidc", "https://x.com", "c1")
    result = await svc.deactivate_provider(provider["id"])
    assert result["is_active"] is False

    # Should not appear in list
    providers = await svc.list_providers()
    assert len(providers) == 0


async def test_deactivate_nonexistent(svc):
    with pytest.raises(NotFoundError):
        await svc.deactivate_provider("nonexistent")


def test_generate_pkce_produces_valid_pair():
    """Validates that PKCE generates a verifier and S256 challenge."""
    import hashlib as _hashlib
    verifier, challenge = SSOService._generate_pkce()
    # Verifier should be URL-safe base64 without padding
    assert len(verifier) > 0
    assert "=" not in verifier
    # Challenge should match S256(verifier)
    digest = _hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert challenge == expected


def test_state_ttl_cleanup():
    """Validates that expired pending states are purged."""
    import time

    SSOService._pending_states["old-state"] = {
        "nonce": "n",
        "code_verifier": "v",
        "provider_id": "p",
        "created_at": time.monotonic() - 9999,
    }
    SSOService._purge_expired_states()
    assert "old-state" not in SSOService._pending_states


def test_pop_state_returns_none_for_missing():
    """Returns None when state is not found."""
    result = SSOService._pop_state("nonexistent-state")
    assert result is None


def test_pop_state_removes_entry():
    """Validates that _pop_state removes the entry after retrieval."""
    import time

    SSOService._pending_states["test-state"] = {
        "nonce": "n",
        "code_verifier": "v",
        "provider_id": "p",
        "created_at": time.monotonic(),
    }
    result = SSOService._pop_state("test-state")
    assert result is not None
    assert result["nonce"] == "n"
    assert "test-state" not in SSOService._pending_states
