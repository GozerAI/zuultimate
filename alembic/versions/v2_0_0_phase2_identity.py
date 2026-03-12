"""v2.0.0 Phase 2 Identity — capability-based authorization layer

Adds: identity_tokens, capability_tokens, data_shapes, policy_decisions tables.

Revision ID: v2_0_0_phase2_identity
Revises: v1_1_0_saas_columns
Create Date: 2026-03-05
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "v2_0_0_phase2_identity"
down_revision: Union[str, None] = "v1_1_0_saas_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── IdentityToken ────────────────────────────────────────────────────
    op.create_table(
        "identity_tokens",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", sa.String(255), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("parent_token_id", sa.String(36), sa.ForeignKey("identity_tokens.id", ondelete="SET NULL"), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_identity_tokens_entity_type", "identity_tokens", ["entity_type"])
    op.create_index("ix_identity_tokens_entity_id", "identity_tokens", ["entity_id"])
    op.create_index("ix_identity_tokens_tenant_id", "identity_tokens", ["tenant_id"])

    # ── CapabilityToken ──────────────────────────────────────────────────
    op.create_table(
        "capability_tokens",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("identity_token_id", sa.String(36), sa.ForeignKey("identity_tokens.id", ondelete="CASCADE"), nullable=False),
        sa.Column("capability", sa.String(255), nullable=False),
        sa.Column("resource_scope", sa.String(500), nullable=False, server_default="*"),
        sa.Column("constraints_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("granted_by", sa.String(36), sa.ForeignKey("identity_tokens.id", ondelete="SET NULL"), nullable=True),
        sa.Column("parent_capability_id", sa.String(36), sa.ForeignKey("capability_tokens.id", ondelete="SET NULL"), nullable=True),
        sa.Column("delegatable", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_capability_tokens_identity_token_id", "capability_tokens", ["identity_token_id"])
    op.create_index("ix_capability_tokens_capability", "capability_tokens", ["capability"])

    # ── DataShape ────────────────────────────────────────────────────────
    op.create_table(
        "data_shapes",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True),
        sa.Column("schema_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("sensitivity", sa.String(20), nullable=False, server_default="internal"),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("pii_fields_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_data_shapes_tenant_id", "data_shapes", ["tenant_id"])

    # ── PolicyDecision ───────────────────────────────────────────────────
    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("identity_token_id", sa.String(36), sa.ForeignKey("identity_tokens.id", ondelete="CASCADE"), nullable=False),
        sa.Column("capability_id", sa.String(36), sa.ForeignKey("capability_tokens.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resource", sa.String(500), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("data_shape_id", sa.String(36), sa.ForeignKey("data_shapes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("filtered_fields_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_decisions_identity_token_id", "policy_decisions", ["identity_token_id"])


def downgrade() -> None:
    op.drop_table("policy_decisions")
    op.drop_table("data_shapes")
    op.drop_table("capability_tokens")
    op.drop_table("identity_tokens")
