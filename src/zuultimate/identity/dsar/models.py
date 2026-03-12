"""DSAR request tracking — data subject access request lifecycle management."""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class DSARType(str, enum.Enum):
    access = "access"
    deletion = "deletion"
    portability = "portability"
    correction = "correction"
    restriction = "restriction"


class DSARStatus(str, enum.Enum):
    received = "received"
    validated = "validated"
    processing = "processing"
    fulfilled = "fulfilled"
    rejected = "rejected"


class DSARRequest(Base, TimestampMixin):
    __tablename__ = "dsar_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    request_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="received")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fulfilled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_trail: Mapped[str] = mapped_column(Text, default="[]")
