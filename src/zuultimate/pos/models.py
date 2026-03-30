"""POS SQLAlchemy models."""

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class Terminal(Base, TimestampMixin):
    __tablename__ = "terminals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    device_type: Mapped[str] = mapped_column(String(100), default="")
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class Transaction(Base, TimestampMixin):
    __tablename__ = "transactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    terminal_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("terminals.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    reference: Mapped[str] = mapped_column(String(255), default="")


class SettlementBatch(Base, TimestampMixin):
    __tablename__ = "settlement_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    terminal_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("terminals.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    transaction_count: Mapped[int] = mapped_column(Integer, default=0)
    total_amount: Mapped[float] = mapped_column(Float, default=0.0)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    reference: Mapped[str] = mapped_column(String(255), default="")


class FraudAlert(Base, TimestampMixin):
    __tablename__ = "fraud_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    transaction_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transactions.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    alert_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
