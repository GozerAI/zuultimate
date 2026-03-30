"""SQLAlchemy models for the billing module."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class FeatureFlag(Base, TimestampMixin):
    """Per-plan feature flag with granular controls (252/255)."""

    __tablename__ = "billing_feature_flags"
    __table_args__ = (
        Index("ix_ff_plan_feature", "plan", "feature_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    feature_key: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    limit_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    description: Mapped[str] = mapped_column(Text, default="")
