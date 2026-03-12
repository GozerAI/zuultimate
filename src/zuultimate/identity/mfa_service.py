"""TOTP-based MFA service with encrypted secrets at rest."""

import base64
import json

import pyotp
from sqlalchemy import select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.common.security import create_jwt, decode_jwt
from zuultimate.identity.models import MFADevice, User
from zuultimate.vault.crypto import decrypt_aes_gcm, derive_key, encrypt_aes_gcm

_DB_KEY = "identity"


class MFAService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self.settings = settings
        self._key, _ = derive_key(settings.secret_key, salt=settings.mfa_salt.encode())

    def _encrypt_secret(self, secret: str) -> str:
        """Encrypt TOTP secret and return base64-encoded JSON envelope."""
        ct, nonce, tag = encrypt_aes_gcm(secret.encode(), self._key)
        envelope = {
            "ct": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        }
        return json.dumps(envelope)

    def _decrypt_secret(self, encrypted: str) -> str:
        """Decrypt TOTP secret from base64-encoded JSON envelope.

        For backwards compatibility, if the stored value is not valid JSON
        (i.e. a raw plaintext secret from before encryption was added),
        return it as-is.
        """
        try:
            envelope = json.loads(encrypted)
        except (json.JSONDecodeError, TypeError):
            return encrypted

        if not all(k in envelope for k in ("ct", "nonce", "tag")):
            return encrypted

        ct = base64.b64decode(envelope["ct"])
        nonce = base64.b64decode(envelope["nonce"])
        tag = base64.b64decode(envelope["tag"])
        return decrypt_aes_gcm(ct, self._key, nonce, tag).decode()

    async def setup_totp(self, user_id: str) -> dict:
        """Generate TOTP secret and provisioning URI for a user."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")

            # Check if user already has an active TOTP device
            result = await session.execute(
                select(MFADevice).where(
                    MFADevice.user_id == user_id,
                    MFADevice.device_type == "totp",
                    MFADevice.is_active == True,
                )
            )
            if result.scalar_one_or_none() is not None:
                raise ValidationError("TOTP MFA already configured")

            secret = pyotp.random_base32()

            device = MFADevice(
                user_id=user_id,
                device_type="totp",
                device_name="Authenticator App",
                is_active=False,  # Not active until verified
                secret_encrypted=self._encrypt_secret(secret),
            )
            session.add(device)
            await session.flush()

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email, issuer_name="Zuultimate"
        )

        return {
            "device_id": device.id,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
        }

    async def verify_totp(self, user_id: str, code: str) -> dict:
        """Verify a TOTP code and activate MFA for the user."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(MFADevice).where(
                    MFADevice.user_id == user_id,
                    MFADevice.device_type == "totp",
                    MFADevice.is_active == False,
                )
            )
            device = result.scalar_one_or_none()
            if device is None:
                raise NotFoundError("No pending TOTP device found")

            secret = self._decrypt_secret(device.secret_encrypted)
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                raise AuthenticationError("Invalid TOTP code")

            device.is_active = True

        return {"status": "mfa_enabled", "device_id": device.id}

    async def has_active_mfa(self, user_id: str) -> bool:
        """Check if user has active MFA device."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(MFADevice).where(
                    MFADevice.user_id == user_id,
                    MFADevice.device_type == "totp",
                    MFADevice.is_active == True,
                )
            )
            return result.scalar_one_or_none() is not None

    def create_mfa_token(self, user_id: str, username: str) -> str:
        """Create a short-lived MFA challenge token."""
        return create_jwt(
            {"sub": user_id, "username": username, "type": "mfa_challenge"},
            self.settings.secret_key,
            expires_minutes=5,
        )

    async def complete_challenge(self, mfa_token: str, code: str) -> dict:
        """Validate MFA token + TOTP code, return access/refresh tokens."""
        try:
            payload = decode_jwt(mfa_token, self.settings.secret_key)
        except Exception:
            raise AuthenticationError("Invalid or expired MFA token")

        if payload.get("type") != "mfa_challenge":
            raise AuthenticationError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid token payload")

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(MFADevice).where(
                    MFADevice.user_id == user_id,
                    MFADevice.device_type == "totp",
                    MFADevice.is_active == True,
                )
            )
            device = result.scalar_one_or_none()
            if device is None:
                raise AuthenticationError("No active MFA device")

            secret = self._decrypt_secret(device.secret_encrypted)
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                raise AuthenticationError("Invalid TOTP code")

        return {"user_id": user_id, "username": payload.get("username", "")}
