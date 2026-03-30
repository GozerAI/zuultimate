"""Backup & resilience SQLAlchemy models."""

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class Snapshot(Base, TimestampMixin):
    __tablename__ = "snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    checksum: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class RestoreJob(Base, TimestampMixin):
    __tablename__ = "restore_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    snapshot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    error: Mapped[str] = mapped_column(Text, default="")


class IntegrityCheck(Base, TimestampMixin):
    __tablename__ = "integrity_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
