"""Passkey (FIDO2/WebAuthn) registration and authentication ceremonies."""

import hashlib
import json
import os
import time

from sqlalchemy import select

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)
from webauthn.helpers import (
    parse_authentication_credential_json,
    parse_registration_credential_json,
)

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.common.logging import get_logger
from zuultimate.common.security import create_jwt
from zuultimate.identity.models import User, UserSession, WebAuthnCredential

logger = get_logger(__name__)

_DB_KEY = "identity"
_CHALLENGE_TTL_SECONDS = 300  # 5 minutes


class PasskeyService:
    """Manages FIDO2/WebAuthn passkey registration and authentication."""

    _pending_challenges: dict[str, dict] = {}

    def __init__(self, db: DatabaseManager, settings: ZuulSettings, key_manager=None):
        self.db = db
        self.settings = settings
        self.key_manager = key_manager

    async def _get_signing_args(self) -> dict:
        if self.key_manager is not None:
            pem, kid = await self.key_manager.get_signing_key()
            return {"private_key": pem, "kid": kid}
        return {}

    # ------------------------------------------------------------------
    # Challenge management
    # ------------------------------------------------------------------

    @classmethod
    def _purge_expired_challenges(cls) -> None:
        """Removes expired pending challenges to prevent unbounded memory growth."""
        now = time.monotonic()
        expired = [
            key for key, val in cls._pending_challenges.items()
            if now - val["created_at"] > _CHALLENGE_TTL_SECONDS
        ]
        for key in expired:
            del cls._pending_challenges[key]

    @classmethod
    def _store_challenge(cls, challenge_id: str, data: dict) -> None:
        """Stores a pending challenge for later verification."""
        cls._purge_expired_challenges()
        cls._pending_challenges[challenge_id] = {
            **data,
            "created_at": time.monotonic(),
        }

    @classmethod
    def _pop_challenge(cls, challenge_id: str) -> dict | None:
        """Retrieves and removes a pending challenge. Returns None if missing or expired."""
        entry = cls._pending_challenges.pop(challenge_id, None)
        if entry is None:
            return None
        if time.monotonic() - entry["created_at"] > _CHALLENGE_TTL_SECONDS:
            return None
        return entry

    # ------------------------------------------------------------------
    # Registration ceremony
    # ------------------------------------------------------------------

    async def begin_registration(self, user_id: str) -> dict:
        """Generate PublicKeyCredentialCreationOptions for a user."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")

            # Get existing credentials to exclude
            result = await session.execute(
                select(WebAuthnCredential).where(
                    WebAuthnCredential.user_id == user_id,
                    WebAuthnCredential.is_active == True,
                )
            )
            existing = result.scalars().all()

        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(cred.credential_id),
            )
            for cred in existing
        ]

        options = generate_registration_options(
            rp_id=self.settings.webauthn_rp_id,
            rp_name="Zuultimate",
            user_id=user_id.encode(),
            user_name=user.username,
            user_display_name=user.display_name or user.username,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )

        challenge_id = os.urandom(16).hex()
        self._store_challenge(challenge_id, {
            "challenge": bytes_to_base64url(options.challenge),
            "user_id": user_id,
            "type": "registration",
        })

        options_dict = json.loads(options_to_json(options))

        logger.info("Passkey registration started for user")
        return {
            "options": options_dict,
            "challenge": challenge_id,
        }

    async def complete_registration(
        self, user_id: str, credential_response: dict, challenge: str,
    ) -> dict:
        """Verify registration response and store the new credential."""
        pending = self._pop_challenge(challenge)
        if pending is None:
            raise ValidationError("Challenge expired or invalid")

        if pending.get("user_id") != user_id:
            raise ValidationError("Challenge does not match user")

        if pending.get("type") != "registration":
            raise ValidationError("Invalid challenge type")

        expected_challenge = base64url_to_bytes(pending["challenge"])

        try:
            credential = parse_registration_credential_json(json.dumps(credential_response))
        except Exception:
            raise ValidationError("Invalid credential response format")

        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origin,
            )
        except Exception as exc:
            raise ValidationError(f"Registration verification failed: {exc}")

        cred_id_b64 = bytes_to_base64url(verification.credential_id)
        pub_key_b64 = bytes_to_base64url(verification.credential_public_key)
        aaguid_str = str(verification.aaguid) if hasattr(verification, "aaguid") and verification.aaguid else ""

        # Check for duplicate credential
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebAuthnCredential).where(
                    WebAuthnCredential.credential_id == cred_id_b64,
                )
            )
            if result.scalar_one_or_none() is not None:
                raise ValidationError("Credential already registered")

            webauthn_cred = WebAuthnCredential(
                user_id=user_id,
                credential_id=cred_id_b64,
                public_key=pub_key_b64,
                sign_count=verification.sign_count,
                aaguid=aaguid_str,
            )
            session.add(webauthn_cred)
            await session.flush()
            cred_id_db = webauthn_cred.id

        logger.info("Passkey registered successfully")
        return {
            "credential_db_id": cred_id_db,
            "credential_id": cred_id_b64,
        }

    # ------------------------------------------------------------------
    # Authentication ceremony
    # ------------------------------------------------------------------

    async def begin_authentication(self, user_id: str = "") -> dict:
        """Generate PublicKeyCredentialRequestOptions for authentication."""
        allow_credentials = []

        if user_id:
            async with self.db.get_session(_DB_KEY) as session:
                result = await session.execute(
                    select(WebAuthnCredential).where(
                        WebAuthnCredential.user_id == user_id,
                        WebAuthnCredential.is_active == True,
                    )
                )
                creds = result.scalars().all()

            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred.credential_id),
                )
                for cred in creds
            ]

        options = generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            allow_credentials=allow_credentials if allow_credentials else None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        challenge_id = os.urandom(16).hex()
        self._store_challenge(challenge_id, {
            "challenge": bytes_to_base64url(options.challenge),
            "user_id": user_id,
            "type": "authentication",
        })

        options_dict = json.loads(options_to_json(options))

        logger.info("Passkey authentication started")
        return {
            "options": options_dict,
            "challenge": challenge_id,
        }

    async def complete_authentication(
        self, credential_response: dict, challenge: str,
    ) -> dict:
        """Verify authentication response and issue tokens."""
        pending = self._pop_challenge(challenge)
        if pending is None:
            raise ValidationError("Challenge expired or invalid")

        if pending.get("type") != "authentication":
            raise ValidationError("Invalid challenge type")

        expected_challenge = base64url_to_bytes(pending["challenge"])

        try:
            credential = parse_authentication_credential_json(json.dumps(credential_response))
        except Exception:
            raise ValidationError("Invalid credential response format")

        # Look up stored credential by credential_id
        raw_id_b64 = bytes_to_base64url(credential.raw_id)

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebAuthnCredential).where(
                    WebAuthnCredential.credential_id == raw_id_b64,
                    WebAuthnCredential.is_active == True,
                )
            )
            stored_cred = result.scalar_one_or_none()

        if stored_cred is None:
            raise AuthenticationError("Unknown credential")

        stored_pub_key = base64url_to_bytes(stored_cred.public_key)

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origin,
                credential_public_key=stored_pub_key,
                credential_current_sign_count=stored_cred.sign_count,
            )
        except Exception as exc:
            raise AuthenticationError(f"Authentication verification failed: {exc}")

        # Validate sign_count to detect cloned authenticators
        if verification.new_sign_count <= stored_cred.sign_count and stored_cred.sign_count > 0:
            raise AuthenticationError("Sign count replay detected -- possible cloned authenticator")

        # Update sign_count and issue tokens
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(WebAuthnCredential).where(WebAuthnCredential.id == stored_cred.id)
            )
            cred_to_update = result.scalar_one()
            cred_to_update.sign_count = verification.new_sign_count

            # Look up user
            result = await session.execute(
                select(User).where(User.id == stored_cred.user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise AuthenticationError("User not found or inactive")

            signing = await self._get_signing_args()
            access_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "access"},
                self.settings.secret_key,
                expires_minutes=self.settings.access_token_expire_minutes,
                **signing,
            )
            refresh_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "refresh"},
                self.settings.secret_key,
                expires_minutes=self.settings.refresh_token_expire_days * 24 * 60,
                **signing,
            )

            user_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            )
            session.add(user_session)

        logger.info("Passkey authentication completed successfully")
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_expire_minutes * 60,
            "user_id": user.id,
        }
