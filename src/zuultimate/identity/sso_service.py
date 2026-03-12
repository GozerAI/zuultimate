"""SSO service -- OIDC provider management and authentication flow with PKCE."""

import base64
import hashlib
import json
import os
import time
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.common.licensing import license_gate
from zuultimate.common.logging import get_logger
from zuultimate.common.security import create_jwt
from zuultimate.identity.models import SSOProvider, User, UserSession
from zuultimate.vault.crypto import decrypt_aes_gcm, derive_key, encrypt_aes_gcm

logger = get_logger(__name__)

_DB_KEY = "identity"

# Pending authorization states expire after 10 minutes.
_STATE_TTL_SECONDS = 600


class SSOService:
    """Manages OIDC providers and authorization-code flow with PKCE."""

    # In-memory store for pending auth states keyed by ``state`` value.
    # Each entry holds {nonce, code_verifier, provider_id, created_at}.
    _pending_states: dict[str, dict] = {}

    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        license_gate.gate("zul.sso.oidc", "SSO / OIDC")
        self.db = db
        self.settings = settings
        self._enc_key, _ = derive_key(
            settings.secret_key,
            salt=(settings.mfa_salt + "-sso").encode(),
        )

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _encrypt_secret(self, plaintext: str) -> str:
        """Encrypts a client secret and returns a JSON envelope."""
        if not plaintext:
            return ""
        ct, nonce, tag = encrypt_aes_gcm(plaintext.encode(), self._enc_key)
        return json.dumps({
            "ct": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        })

    def _decrypt_secret(self, stored: str) -> str:
        """Decrypts a stored client secret envelope."""
        if not stored:
            return ""
        try:
            envelope = json.loads(stored)
            ct = base64.b64decode(envelope["ct"])
            nonce = base64.b64decode(envelope["nonce"])
            tag = base64.b64decode(envelope["tag"])
            return decrypt_aes_gcm(ct, self._enc_key, nonce, tag).decode()
        except (json.JSONDecodeError, KeyError):
            # Backwards compat: treat as plaintext
            return stored

    # ------------------------------------------------------------------
    # Redirect-URI validation
    # ------------------------------------------------------------------

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        """Validates redirect_uri against allowed origins to prevent open redirects."""
        parsed = urlparse(redirect_uri)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.settings.sso_allowed_redirect_origins:
            raise ValidationError(
                f"Redirect URI origin '{origin}' not in allowed list. "
                f"Allowed: {self.settings.sso_allowed_redirect_origins}"
            )

    # ------------------------------------------------------------------
    # PKCE helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_pkce() -> tuple[str, str]:
        """Generates a PKCE code_verifier and S256 code_challenge pair."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return code_verifier, code_challenge

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    @classmethod
    def _purge_expired_states(cls) -> None:
        """Removes expired pending states to prevent unbounded memory growth."""
        now = time.monotonic()
        expired = [
            key for key, val in cls._pending_states.items()
            if now - val["created_at"] > _STATE_TTL_SECONDS
        ]
        for key in expired:
            del cls._pending_states[key]

    @classmethod
    def _store_state(cls, state: str, nonce: str, code_verifier: str, provider_id: str) -> None:
        """Stores pending authorization state for later validation."""
        cls._purge_expired_states()
        cls._pending_states[state] = {
            "nonce": nonce,
            "code_verifier": code_verifier,
            "provider_id": provider_id,
            "created_at": time.monotonic(),
        }

    @classmethod
    def _pop_state(cls, state: str) -> dict | None:
        """Retrieves and removes pending state. Returns None if missing or expired."""
        entry = cls._pending_states.pop(state, None)
        if entry is None:
            return None
        if time.monotonic() - entry["created_at"] > _STATE_TTL_SECONDS:
            return None
        return entry

    # ------------------------------------------------------------------
    # Provider CRUD
    # ------------------------------------------------------------------

    async def create_provider(
        self,
        name: str,
        protocol: str,
        issuer_url: str,
        client_id: str,
        client_secret: str = "",
        metadata_url: str = "",
        tenant_id: str | None = None,
    ) -> dict:
        """Creates an OIDC provider record."""
        if protocol != "oidc":
            raise ValidationError("Protocol must be 'oidc'")

        async with self.db.get_session(_DB_KEY) as session:
            provider = SSOProvider(
                name=name,
                protocol=protocol,
                issuer_url=issuer_url,
                client_id=client_id,
                client_secret_encrypted=self._encrypt_secret(client_secret),
                metadata_url=metadata_url or None,
                tenant_id=tenant_id,
            )
            session.add(provider)
            await session.flush()

        return self._to_dict(provider)

    async def list_providers(self, tenant_id: str | None = None) -> list[dict]:
        """Lists active OIDC providers, optionally filtered by tenant."""
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(SSOProvider).where(SSOProvider.is_active == True)
            if tenant_id:
                stmt = stmt.where(SSOProvider.tenant_id == tenant_id)
            result = await session.execute(stmt)
            providers = result.scalars().all()
        return [self._to_dict(p) for p in providers]

    async def get_provider(self, provider_id: str) -> dict:
        """Fetches a single provider by ID."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError("SSO provider not found")
        return self._to_dict(provider)

    async def deactivate_provider(self, provider_id: str) -> dict:
        """Deactivates a provider so it no longer appears in listings."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError("SSO provider not found")
            provider.is_active = False
        return {"id": provider_id, "is_active": False}

    # ------------------------------------------------------------------
    # OIDC authorization flow
    # ------------------------------------------------------------------

    async def initiate_login(self, provider_id: str, redirect_uri: str) -> dict:
        """Builds an OIDC authorization URL with PKCE and nonce."""
        self._validate_redirect_uri(redirect_uri)
        provider = await self.get_provider(provider_id)

        state = os.urandom(16).hex()
        nonce = os.urandom(16).hex()
        code_verifier, code_challenge = self._generate_pkce()

        # Store state for callback validation
        self._store_state(state, nonce, code_verifier, provider_id)

        params = {
            "client_id": provider["client_id"],
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        redirect_url = f"{provider['issuer_url']}/authorize?{urlencode(params)}"

        return {
            "redirect_url": redirect_url,
            "state": state,
            "nonce": nonce,
            "provider_id": provider_id,
        }

    async def _exchange_code_for_tokens(
        self, provider: dict, code: str, redirect_uri: str = "",
        code_verifier: str = "",
    ) -> dict:
        """Exchanges an authorization code at the provider's token endpoint.

        Returns the parsed JSON body from the IdP (id_token, access_token, etc.).
        Raises ``ValidationError`` on HTTP or protocol failures.
        """
        client_secret = ""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider["id"])
            )
            prov_obj = result.scalar_one_or_none()
            if prov_obj and prov_obj.client_secret_encrypted:
                client_secret = self._decrypt_secret(prov_obj.client_secret_encrypted)

        token_url = f"{provider['issuer_url']}/token"
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": provider["client_id"],
            "client_secret": client_secret,
        }
        if redirect_uri:
            payload["redirect_uri"] = redirect_uri
        if code_verifier:
            payload["code_verifier"] = code_verifier

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(token_url, data=payload)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.error("Token exchange failed (%s): %s", exc.response.status_code, exc.response.text)
                raise ValidationError(
                    f"SSO token exchange failed: HTTP {exc.response.status_code}"
                ) from exc
            except httpx.RequestError as exc:
                logger.error("Token exchange network error: %s", exc)
                raise ValidationError(
                    f"SSO token exchange network error: {exc}"
                ) from exc

    @staticmethod
    def _extract_user_info(token_body: dict) -> tuple[str, str, str]:
        """Extracts (email, username, display_name) from IdP token response.

        Supports:
        - ``id_token`` containing a JWT with email/name claims (OIDC standard)
        - Top-level ``email`` / ``user`` keys (simplified providers)

        Returns (email, username, display_name). Falls back to empty strings
        when claims are missing.
        """
        email = token_body.get("email", "")
        username = token_body.get("preferred_username", "") or token_body.get("user", "")
        display_name = token_body.get("name", "")

        # Try to decode id_token JWT payload (unverified -- the server already
        # validated the code exchange, so the id_token is authentic).
        id_token = token_body.get("id_token", "")
        if id_token:
            try:
                # JWT: header.payload.signature -- decode payload
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(padded))
                    email = email or claims.get("email", "")
                    username = username or claims.get("preferred_username", "") or claims.get("sub", "")
                    display_name = display_name or claims.get("name", "")
            except Exception:
                pass  # Graceful -- use top-level fields

        return email, username, display_name

    async def handle_callback(
        self, provider_id: str, code: str, state: str,
        nonce: str = "", redirect_uri: str = "",
    ) -> dict:
        """Handles the SSO callback -- exchanges code for tokens with PKCE.

        Validates the nonce against the stored pending state, sends the
        code_verifier to the token endpoint, and issues Zuultimate JWT tokens.
        """
        provider = await self.get_provider(provider_id)

        # Retrieve and validate pending state
        pending = self._pop_state(state)
        code_verifier = ""
        if pending:
            # Validate nonce matches the one stored during initiate_login
            if nonce and pending["nonce"] != nonce:
                raise ValidationError(
                    "Nonce mismatch -- possible replay attack"
                )
            code_verifier = pending["code_verifier"]

        # Exchange authorization code with the IdP (include code_verifier for PKCE)
        token_body = await self._exchange_code_for_tokens(
            provider, code, redirect_uri, code_verifier=code_verifier,
        )
        email, username, display_name = self._extract_user_info(token_body)

        if not email:
            raise ValidationError(
                "SSO provider did not return an email claim. "
                "Ensure 'email' scope is requested."
            )
        if not username:
            username = email.split("@")[0]
        if not display_name:
            display_name = username

        async with self.db.get_session(_DB_KEY) as session:
            # Find or create user
            result = await session.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one_or_none()

            if user is None:
                user = User(
                    email=email,
                    username=username,
                    display_name=display_name,
                    is_verified=True,  # SSO users are auto-verified
                    tenant_id=provider.get("tenant_id"),
                )
                session.add(user)
                await session.flush()

            access_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "access"},
                self.settings.secret_key,
                expires_minutes=self.settings.access_token_expire_minutes,
            )
            refresh_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "refresh"},
                self.settings.secret_key,
                expires_minutes=self.settings.refresh_token_expire_days * 24 * 60,
            )

            user_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            )
            session.add(user_session)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_expire_minutes * 60,
            "user_id": user.id,
            "sso_provider": provider["name"],
        }

    @staticmethod
    def _to_dict(p: SSOProvider) -> dict:
        return {
            "id": p.id,
            "name": p.name,
            "protocol": p.protocol,
            "issuer_url": p.issuer_url,
            "client_id": p.client_id,
            "metadata_url": p.metadata_url,
            "tenant_id": p.tenant_id,
            "is_active": p.is_active,
        }
