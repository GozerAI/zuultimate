"""SSO service -- OIDC/SAML provider management and authentication flow."""

import hashlib
import json
import os
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


class SSOService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        license_gate.gate("zul.sso.oidc", "SSO / OIDC")
        self.db = db
        self.settings = settings
        self._enc_key, _ = derive_key(
            settings.secret_key,
            salt=(settings.mfa_salt + "-sso").encode(),
        )

    def _encrypt_secret(self, plaintext: str) -> str:
        """Encrypt a client secret and return a JSON envelope."""
        if not plaintext:
            return ""
        ct, nonce, tag = encrypt_aes_gcm(plaintext.encode(), self._enc_key)
        import base64
        return json.dumps({
            "ct": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        })

    def _decrypt_secret(self, stored: str) -> str:
        """Decrypt a stored client secret envelope."""
        if not stored:
            return ""
        try:
            envelope = json.loads(stored)
            import base64
            ct = base64.b64decode(envelope["ct"])
            nonce = base64.b64decode(envelope["nonce"])
            tag = base64.b64decode(envelope["tag"])
            return decrypt_aes_gcm(ct, self._enc_key, nonce, tag).decode()
        except (json.JSONDecodeError, KeyError):
            # Backwards compat: treat as plaintext
            return stored

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        """Validate redirect_uri against allowed origins to prevent open redirects."""
        parsed = urlparse(redirect_uri)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self.settings.sso_allowed_redirect_origins:
            raise ValidationError(
                f"Redirect URI origin '{origin}' not in allowed list. "
                f"Allowed: {self.settings.sso_allowed_redirect_origins}"
            )

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
        if protocol not in ("oidc", "saml"):
            raise ValidationError("Protocol must be 'oidc' or 'saml'")

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
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(SSOProvider).where(SSOProvider.is_active == True)
            if tenant_id:
                stmt = stmt.where(SSOProvider.tenant_id == tenant_id)
            result = await session.execute(stmt)
            providers = result.scalars().all()
        return [self._to_dict(p) for p in providers]

    async def get_provider(self, provider_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError("SSO provider not found")
        return self._to_dict(provider)

    async def initiate_login(self, provider_id: str, redirect_uri: str) -> dict:
        """Generate SSO login URL for the given provider."""
        self._validate_redirect_uri(redirect_uri)
        provider = await self.get_provider(provider_id)
        state = os.urandom(16).hex()

        if provider["protocol"] == "oidc":
            params = {
                "client_id": provider["client_id"],
                "response_type": "code",
                "scope": "openid email profile",
                "redirect_uri": redirect_uri,
                "state": state,
            }
            redirect_url = f"{provider['issuer_url']}/authorize?{urlencode(params)}"
        else:
            # SAML: redirect to IdP SSO URL
            redirect_url = f"{provider['issuer_url']}/sso?SAMLRequest=placeholder&RelayState={state}"

        return {
            "redirect_url": redirect_url,
            "state": state,
            "provider_id": provider_id,
        }

    async def _exchange_code_for_tokens(
        self, provider: dict, code: str, redirect_uri: str = "",
    ) -> dict:
        """Exchange an authorization code at the provider's token endpoint.

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
        """Extract (email, username, display_name) from IdP token response.

        Supports:
        - ``id_token`` containing a JWT with email/name claims (OIDC standard)
        - Top-level ``email`` / ``user`` keys (simplified providers)

        Returns (email, username, display_name). Falls back to empty strings
        when claims are missing.
        """
        email = token_body.get("email", "")
        username = token_body.get("preferred_username", "") or token_body.get("user", "")
        display_name = token_body.get("name", "")

        # Try to decode id_token JWT payload (unverified — the server already
        # validated the code exchange, so the id_token is authentic).
        id_token = token_body.get("id_token", "")
        if id_token:
            try:
                import base64
                # JWT: header.payload.signature — decode payload
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(padded))
                    email = email or claims.get("email", "")
                    username = username or claims.get("preferred_username", "") or claims.get("sub", "")
                    display_name = display_name or claims.get("name", "")
            except Exception:
                pass  # Graceful — use top-level fields

        return email, username, display_name

    async def handle_callback(
        self, provider_id: str, code: str, state: str,
        redirect_uri: str = "",
    ) -> dict:
        """Handle the SSO callback — exchange code for tokens.

        Performs a real OIDC authorization-code exchange against the provider's
        token endpoint, extracts user info from the response, and issues
        Zuultimate JWT tokens.
        """
        provider = await self.get_provider(provider_id)

        # Exchange authorization code with the IdP
        token_body = await self._exchange_code_for_tokens(provider, code, redirect_uri)
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

    async def deactivate_provider(self, provider_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError("SSO provider not found")
            provider.is_active = False
        return {"id": provider_id, "is_active": False}

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
