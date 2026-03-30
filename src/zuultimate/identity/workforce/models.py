"""Workforce SQLAlchemy models: device posture, PoP, JIT grants, break-glass."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class DevicePosture(Base, TimestampMixin):
    __tablename__ = "device_postures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    os_type: Mapped[str] = mapped_column(String(50), default="")
    mdm_managed: Mapped[bool] = mapped_column(Boolean, default=False)
    disk_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    posture_score: Mapped[float] = mapped_column(Float, default=0.0)


class PopRegistration(Base, TimestampMixin):
    __tablename__ = "pop_registrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    pop_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    pop_name: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[str] = mapped_column(String(20), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active")
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class JITGrant(Base, TimestampMixin):
    __tablename__ = "jit_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class BreakGlassSession(Base, TimestampMixin):
    __tablename__ = "break_glass_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    first_approver_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    second_approver_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    audit_tag: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
