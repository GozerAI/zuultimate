"""Split-key blind pass service -- neither side alone can decrypt."""

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select, String, Text, DateTime, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.database import DatabaseManager
from zuultimate.common.config import ZuulSettings
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.common.models import Base, TimestampMixin, generate_uuid
from zuultimate.vault.crypto import encrypt_aes_gcm, decrypt_aes_gcm


class BlindPassToken(Base, TimestampMixin):
    __tablename__ = "blind_pass_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False)
    tenant_id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encrypted_subject: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    sovereignty_ring: Mapped[str] = mapped_column(String(20), default="us")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BlindPassService:
    """Split-key encryption: zuultimate vault key + vinzy client_key_shard."""

    _DB_KEY = "credential"  # vault operations use credential DB

    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self.settings = settings
        self._vault_key = self._derive_vault_key(settings)

    @staticmethod
    def _derive_vault_key(settings: ZuulSettings) -> bytes:
        salt = hashlib.sha256(
            settings.vault_salt.encode() + b"-" + settings.secret_key.encode()
        ).digest()[:16]
        from zuultimate.vault.crypto import derive_key
        key, _ = derive_key(settings.secret_key, salt=salt)
        return key

    def _derive_combined_key(self, client_key_shard: bytes, salt: bytes) -> bytes:
        """HKDF(vault_key || client_shard, salt) -> 32-byte AES key."""
        combined = self._vault_key + client_key_shard
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"blind-pass-v1",
        ).derive(combined)

    async def create_blind_pass(
        self,
        subject_id: str,
        tenant_id: str,
        purpose: str,
        ttl_seconds: int,
        client_key_shard: bytes,
        sovereignty_ring: str = "us",
    ) -> dict:
        """Create a blind pass token. Neither side alone can decrypt subject_id."""
        if len(client_key_shard) != 32:
            raise ValidationError("client_key_shard must be 32 bytes")

        # Per-token random salt
        key_salt = os.urandom(32)
        combined_key = self._derive_combined_key(client_key_shard, key_salt)

        # Encrypt subject_id with combined key
        ct, nonce, tag = encrypt_aes_gcm(subject_id.encode(), combined_key)

        # Generate opaque token
        token_raw = f"bp_{os.urandom(24).hex()}"
        token_hash = hashlib.sha256(token_raw.encode()).hexdigest()
        tenant_id_hash = hashlib.sha256(tenant_id.encode()).hexdigest()

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        encrypted_subject_b64 = base64.b64encode(ct).decode()

        async with self.db.get_session(self._DB_KEY) as session:
            record = BlindPassToken(
                token_hash=token_hash,
                purpose=purpose,
                tenant_id_hash=tenant_id_hash,
                encrypted_subject=encrypted_subject_b64,
                nonce=nonce,
                tag=tag,
                key_salt=key_salt,
                sovereignty_ring=sovereignty_ring,
                expires_at=expires_at,
            )
            session.add(record)

        return {
            "token": token_raw,
            "purpose": purpose,
            "sovereignty_ring": sovereignty_ring,
            "expires_at": expires_at.isoformat(),
        }

    async def verify_blind_pass(self, token: str, purpose: str) -> dict:
        """Verify token exists, not expired, not revoked, purpose matches.

        NO identity data returned.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        async with self.db.get_session(self._DB_KEY) as session:
            result = await session.execute(
                select(BlindPassToken).where(BlindPassToken.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()

        if record is None:
            return {"valid": False, "reason": "Token not found"}
        if record.revoked_at is not None:
            return {"valid": False, "reason": "Token revoked"}
        if record.expires_at:
            exp = record.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return {"valid": False, "reason": "Token expired"}
        if record.purpose != purpose:
            return {"valid": False, "reason": "Purpose mismatch"}

        exp_iso = None
        if record.expires_at:
            exp = record.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            exp_iso = exp.isoformat()

        return {
            "valid": True,
            "purpose": record.purpose,
            "sovereignty_ring": record.sovereignty_ring,
            "expires_at": exp_iso,
        }

    async def resolve_blind_pass(self, token: str, client_key_shard: bytes) -> str:
        """Resolve blind pass to subject_id. REQUIRES BOTH key shards."""
        if len(client_key_shard) != 32:
            raise ValidationError("client_key_shard must be 32 bytes")

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        async with self.db.get_session(self._DB_KEY) as session:
            result = await session.execute(
                select(BlindPassToken).where(BlindPassToken.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()

        if record is None:
            raise NotFoundError("Blind pass token not found")
        if record.revoked_at is not None:
            raise ValidationError("Token has been revoked")
        if record.expires_at:
            exp = record.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                raise ValidationError("Token has expired")

        # Reconstruct combined key
        combined_key = self._derive_combined_key(client_key_shard, record.key_salt)

        ct = base64.b64decode(record.encrypted_subject)

        try:
            plaintext = decrypt_aes_gcm(ct, combined_key, record.nonce, record.tag)
        except Exception:
            raise ValidationError("Decryption failed -- wrong key shard")

        return plaintext.decode()

    async def revoke_blind_pass(self, token: str) -> dict:
        """Revoke a blind pass token."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        async with self.db.get_session(self._DB_KEY) as session:
            result = await session.execute(
                select(BlindPassToken).where(BlindPassToken.token_hash == token_hash)
            )
            record = result.scalar_one_or_none()
            if record is None:
                raise NotFoundError("Blind pass token not found")
            record.revoked_at = datetime.now(timezone.utc)

        return {"revoked": True}
