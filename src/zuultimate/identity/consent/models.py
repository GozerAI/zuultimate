"""Consent record storage — tracks granular consent grants and revocations."""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class ConsentPurpose(str, enum.Enum):
    marketing = "marketing"
    analytics = "analytics"
    essential = "essential"
    third_party_share = "third_party_share"


class ConsentRecord(Base, TimestampMixin):
    __tablename__ = "consent_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(50), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[str] = mapped_column(String(50), default="1.0")
    channel: Mapped[str] = mapped_column(String(50), default="api")
    ip_hash: Mapped[str] = mapped_column(String(64), default="")
    evidence_blob: Mapped[str] = mapped_column(Text, default="{}")
