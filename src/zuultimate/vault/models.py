"""Vault SQLAlchemy models -- encrypted blobs, tokens, key versions."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class EncryptedBlob(TimestampMixin, Base):
    __tablename__ = "encrypted_blobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    owner_id: Mapped[str] = mapped_column(String(255), index=True)
    label: Mapped[str] = mapped_column(String(255))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    tag: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    rotation_count: Mapped[int] = mapped_column(Integer, default=0)
    last_rotated: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class VaultToken(TimestampMixin, Base):
    __tablename__ = "vault_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    original_hash: Mapped[str] = mapped_column(String(255))
    token_value: Mapped[str] = mapped_column(String(255), unique=True)
    encrypted_value: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_tag: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class UserSecret(TimestampMixin, Base):
    __tablename__ = "user_secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    category: Mapped[str] = mapped_column(String(50), default="password")
    notes: Mapped[str] = mapped_column(Text, default="")


class KeyVersion(TimestampMixin, Base):
    __tablename__ = "key_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    version: Mapped[int] = mapped_column(Integer, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
