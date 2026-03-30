"""Cross-service binding with per-binding ephemeral salts."""

import asyncio
import hashlib
import hmac
import os
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, String, DateTime, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.database import DatabaseManager
from zuultimate.common.config import ZuulSettings
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class CrossServiceBinding(Base, TimestampMixin):
    __tablename__ = "cross_service_bindings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    salted_vinzy_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    salted_pass_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    binding_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False)
    sovereignty_ring: Mapped[str] = mapped_column(String(20), default="us")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CrossServiceBindingService:
    _DB_KEY = "credential"

    def __init__(self, db: DatabaseManager, settings: ZuulSettings, *, sleep_func=None):
        self.db = db
        self.settings = settings
        self._sleep = sleep_func  # for testing

    async def _delay(self):
        """Random 1-5s delay for timing decorrelation."""
        delay = random.uniform(1.0, 5.0)
        if self._sleep:
            await self._sleep(delay)
        else:
            await asyncio.sleep(delay)

    @staticmethod
    def _salted_hmac(data: str, salt: bytes) -> str:
        return hmac.new(salt, data.encode(), hashlib.sha256).hexdigest()

    async def bind(
        self,
        vinzy_lease_signature: str,
        blind_pass_token: str,
        purpose: str = "provisioning",
        sovereignty_ring: str = "us",
        ttl_seconds: int = 86400 * 365,
    ) -> str:
        """Create cross-service binding with ephemeral salt."""
        await self._delay()

        binding_salt = os.urandom(32)
        salted_vinzy = self._salted_hmac(vinzy_lease_signature, binding_salt)
        salted_pass = self._salted_hmac(blind_pass_token, binding_salt)

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        async with self.db.get_session(self._DB_KEY) as session:
            binding = CrossServiceBinding(
                salted_vinzy_hash=salted_vinzy,
                salted_pass_hash=salted_pass,
                binding_salt=binding_salt,
                purpose=purpose,
                sovereignty_ring=sovereignty_ring,
                expires_at=expires_at,
            )
            session.add(binding)
            await session.flush()
            binding_id = binding.id

        return binding_id

    async def verify_binding(self, vinzy_lease_signature: str, blind_pass_token: str) -> bool:
        """Verify a cross-service binding exists. Does NOT reveal data."""
        async with self.db.get_session(self._DB_KEY) as session:
            result = await session.execute(
                select(CrossServiceBinding).where(
                    CrossServiceBinding.revoked_at == None  # noqa: E711
                )
            )
            bindings = result.scalars().all()

        for binding in bindings:
            expected_vinzy = self._salted_hmac(vinzy_lease_signature, binding.binding_salt)
            expected_pass = self._salted_hmac(blind_pass_token, binding.binding_salt)
            if (hmac.compare_digest(binding.salted_vinzy_hash, expected_vinzy) and
                    hmac.compare_digest(binding.salted_pass_hash, expected_pass)):
                if binding.expires_at:
                    exp = binding.expires_at
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if exp < datetime.now(timezone.utc):
                        return False
                return True
        return False

    async def revoke_binding(self, binding_id: str) -> dict:
        """Cryptographic erasure: wipe salt + hashes."""
        async with self.db.get_session(self._DB_KEY) as session:
            result = await session.execute(
                select(CrossServiceBinding).where(CrossServiceBinding.id == binding_id)
            )
            binding = result.scalar_one_or_none()
            if binding is None:
                raise NotFoundError("Binding not found")

            binding.salted_vinzy_hash = ""
            binding.salted_pass_hash = ""
            binding.binding_salt = b"\x00" * 32
            binding.revoked_at = datetime.now(timezone.utc)

        return {"revoked": True, "binding_id": binding_id}
