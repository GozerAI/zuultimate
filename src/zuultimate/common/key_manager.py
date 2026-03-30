"""RSA key management for RS256 JWT signing with key rotation."""

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import String, Text, DateTime, select
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.common.models import Base, TimestampMixin, generate_uuid

_log = get_logger("zuultimate.key_manager")

# Key statuses
PENDING = "pending"  # In JWKS for pre-caching but not used for signing
ACTIVE = "active"
RETIRING = "retiring"
RETIRED = "retired"


class JWKSKey(Base, TimestampMixin):
    """RSA key pair for RS256 JWT signing."""

    __tablename__ = "jwks_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    kid: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(10), default="RS256")
    private_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ACTIVE, index=True)
    region: Mapped[str] = mapped_column(String(20), default="us")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def _generate_kid(public_key_pem: str) -> str:
    """Generate kid from first 8 chars of SHA-256 of public key DER."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
    der = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:8]


def _generate_rsa_key_pair() -> tuple[str, str]:
    """Generate an RSA-2048 key pair. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


class KeyManager:
    """Manages RSA keys for RS256 JWT signing with rotation support."""

    def __init__(self, db: DatabaseManager, region: str = "us"):
        self.db = db
        self.region = region
        self._signing_key_cache: tuple[str, str] | None = None  # (pem, kid)
        self._verification_keys_cache: dict[str, str] | None = None  # {kid: pem}

    async def ensure_key_exists(self) -> None:
        """Bootstrap: generate RSA key if no ACTIVE key exists. Idempotent."""
        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == ACTIVE)
            )
            if result.scalar_one_or_none() is not None:
                _log.info("ACTIVE RSA key already exists — skipping bootstrap")
                return

            private_pem, public_pem = _generate_rsa_key_pair()
            kid = _generate_kid(public_pem)

            key = JWKSKey(
                kid=kid,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                status=ACTIVE,
                region=self.region,
                expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            )
            session.add(key)
            _log.info("Bootstrapped RSA key kid=%s", kid)

        self._invalidate_cache()

    async def get_signing_key(self) -> tuple[str, str]:
        """Return (private_key_pem, kid) for the current ACTIVE key."""
        if self._signing_key_cache is not None:
            return self._signing_key_cache

        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == ACTIVE).order_by(JWKSKey.created_at.desc())
            )
            key = result.scalar_one_or_none()
            if key is None:
                raise RuntimeError("No ACTIVE RSA key found — call ensure_key_exists()")

            self._signing_key_cache = (key.private_key_pem, key.kid)
            return self._signing_key_cache

    async def get_verification_keys(self) -> dict[str, str]:
        """Return {kid: public_key_pem} for all non-RETIRED keys."""
        if self._verification_keys_cache is not None:
            return self._verification_keys_cache

        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status != RETIRED)
            )
            keys = result.scalars().all()

        self._verification_keys_cache = {k.kid: k.public_key_pem for k in keys}
        return self._verification_keys_cache

    async def get_all_public_keys(self) -> list[dict]:
        """Return all non-RETIRED keys as JWKS-format dicts."""
        async with self.db.get_session("identity") as session:
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status != RETIRED)
            )
            keys = result.scalars().all()

        jwks = []
        for k in keys:
            pub_key = serialization.load_pem_public_key(k.public_key_pem.encode())
            numbers = pub_key.public_numbers()

            import base64

            def _int_to_base64url(n: int) -> str:
                byte_length = (n.bit_length() + 7) // 8
                return base64.urlsafe_b64encode(
                    n.to_bytes(byte_length, byteorder="big")
                ).rstrip(b"=").decode()

            jwks.append({
                "kty": "RSA",
                "kid": k.kid,
                "alg": "RS256",
                "use": "sig",
                "n": _int_to_base64url(numbers.n),
                "e": _int_to_base64url(numbers.e),
            })
        return jwks

    async def rotate(self) -> str:
        """Rotate keys: new ACTIVE, old ACTIVE→RETIRING, old RETIRING→RETIRED.

        Returns the new kid.
        """
        async with self.db.get_session("identity") as session:
            # Move RETIRING → RETIRED
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == RETIRING)
            )
            for key in result.scalars().all():
                key.status = RETIRED

            # Move ACTIVE → RETIRING
            result = await session.execute(
                select(JWKSKey).where(JWKSKey.status == ACTIVE)
            )
            for key in result.scalars().all():
                key.status = RETIRING

            # Create new ACTIVE key
            private_pem, public_pem = _generate_rsa_key_pair()
            kid = _generate_kid(public_pem)

            new_key = JWKSKey(
                kid=kid,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                status=ACTIVE,
                region=self.region,
                expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            )
            session.add(new_key)

        self._invalidate_cache()
        _log.info("Key rotation complete — new kid=%s", kid)
        return kid

    def _invalidate_cache(self) -> None:
        self._signing_key_cache = None
        self._verification_keys_cache = None
