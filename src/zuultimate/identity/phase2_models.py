"""Phase 2 Identity Models — capability-based authorization layer.

Extends Phase 1 (User/Tenant/JWT) with:
- IdentityToken: unified entity representation (user, agent, service)
- CapabilityToken: scoped, time-limited, delegatable permissions
- DataShape: data structure classification and sensitivity
- PolicyDecision: audit log of authorization evaluations
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class IdentityToken(Base, TimestampMixin):
    """Unified identity for users, agents, and services."""

    __tablename__ = "identity_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    entity_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True,
    )  # "user" | "agent" | "service"
    entity_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True,
    )  # user_id, agent codename, or service name
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    display_name: Mapped[str] = mapped_column(String(255), default="")
    parent_token_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identity_tokens.id", ondelete="SET NULL"), nullable=True,
    )  # delegation chain
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")  # JSON blob
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class CapabilityToken(Base, TimestampMixin):
    """Scoped, time-limited, delegatable permission."""

    __tablename__ = "capability_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    identity_token_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_tokens.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    capability: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True,
    )  # e.g., "vault:encrypt", "csuite:delegate:cmo"
    resource_scope: Mapped[str] = mapped_column(
        String(500), nullable=False, default="*",
    )  # glob pattern, e.g., "tenant/*/trends/*"
    constraints_json: Mapped[str] = mapped_column(
        Text, default="{}",
    )  # JSON: {max_calls, ip_range, etc.}
    granted_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("identity_tokens.id", ondelete="SET NULL"), nullable=True,
    )
    parent_capability_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("capability_tokens.id", ondelete="SET NULL"), nullable=True,
    )  # delegation chain
    delegatable: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DataShape(Base, TimestampMixin):
    """Data structure classification and sensitivity level."""

    __tablename__ = "data_shapes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True,
    )  # null = system-wide
    schema_json: Mapped[str] = mapped_column(Text, default="{}")  # JSON Schema
    sensitivity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="internal",
    )  # "public" | "internal" | "confidential" | "restricted"
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    pii_fields_json: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of field paths


class PolicyDecision(Base):
    """Audit log of authorization evaluations."""

    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    identity_token_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_tokens.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    capability_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("capability_tokens.id", ondelete="SET NULL"), nullable=True,
    )
    resource: Mapped[str] = mapped_column(String(500), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    data_shape_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("data_shapes.id", ondelete="SET NULL"), nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(20), nullable=False,
    )  # "allow" | "deny" | "allow_filtered"
    reason: Mapped[str] = mapped_column(String(500), default="")
    filtered_fields_json: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
