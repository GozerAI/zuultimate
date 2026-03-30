"""Global operations: JWKS keys, tenant multi-region, workforce, blind pass.

Revision ID: v3_0_0_global_ops
Revises: v2_0_0_phase2_identity
Create Date: 2026-03-12
"""

from typing import Union

from alembic import op
import sqlalchemy as sa

revision: str = "v3_0_0_global_ops"
down_revision: Union[str, None] = "v2_0_0_phase2_identity"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    # -- JWKS keys (Phase A.0) --
    op.create_table(
        "jwks_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kid", sa.String(16), unique=True, nullable=False, index=True),
        sa.Column("algorithm", sa.String(10), server_default="RS256"),
        sa.Column("private_key_pem", sa.Text, nullable=False),
        sa.Column("public_key_pem", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), server_default="active", index=True),
        sa.Column("region", sa.String(20), server_default="us"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- Tenant multi-region columns (Phase A.1) --
    op.add_column("tenants", sa.Column("home_region", sa.String(20), server_default="us"))
    op.add_column("tenants", sa.Column("sovereignty_ring", sa.String(20), server_default="us"))
    op.add_column("tenants", sa.Column("pii_allowed_regions", sa.Text, server_default='["us"]'))
    op.add_column("tenants", sa.Column("namespace", sa.String(20), server_default="consumer"))

    # -- PoP registrations (Phase C.3) --
    op.create_table(
        "pop_registrations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("pop_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("pop_name", sa.String(255), nullable=False),
        sa.Column("region", sa.String(20), nullable=False),
        sa.Column("public_key", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- JIT grants (Phase D.1) --
    op.create_table(
        "jit_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False, index=True),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("approved_by", sa.String(36), nullable=True),
        sa.Column("status", sa.String(20), server_default="pending", index=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- Break glass sessions (Phase D.2) --
    op.create_table(
        "break_glass_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False, index=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("first_approver_id", sa.String(36), nullable=True),
        sa.Column("second_approver_id", sa.String(36), nullable=True),
        sa.Column("status", sa.String(20), server_default="pending", index=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audit_tag", sa.String(64), unique=True, nullable=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- Blind pass tokens (Phase F.1) --
    op.create_table(
        "blind_pass_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("purpose", sa.String(100), nullable=False),
        sa.Column("tenant_id_hash", sa.String(64), nullable=True),
        sa.Column("encrypted_subject", sa.Text, nullable=False),
        sa.Column("nonce", sa.LargeBinary, nullable=False),
        sa.Column("tag", sa.LargeBinary, nullable=False),
        sa.Column("key_salt", sa.LargeBinary(32), nullable=False),
        sa.Column("sovereignty_ring", sa.String(20), server_default="us"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- Cross-service bindings (Phase F.2) --
    op.create_table(
        "cross_service_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("salted_vinzy_hash", sa.String(128), nullable=False),
        sa.Column("salted_pass_hash", sa.String(128), nullable=False),
        sa.Column("binding_salt", sa.LargeBinary(32), nullable=False),
        sa.Column("purpose", sa.String(100), nullable=False),
        sa.Column("sovereignty_ring", sa.String(20), server_default="us"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -- Workforce device posture (Phase B.3) --
    op.create_table(
        "device_postures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(255), nullable=False, index=True),
        sa.Column("user_id", sa.String(36), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("os_type", sa.String(50), server_default=""),
        sa.Column("mdm_managed", sa.Boolean, server_default="0"),
        sa.Column("disk_encrypted", sa.Boolean, server_default="0"),
        sa.Column("posture_score", sa.Float, server_default="0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("device_postures")
    op.drop_table("cross_service_bindings")
    op.drop_table("blind_pass_tokens")
    op.drop_table("break_glass_sessions")
    op.drop_table("jit_grants")
    op.drop_table("pop_registrations")
    op.drop_column("tenants", "namespace")
    op.drop_column("tenants", "pii_allowed_regions")
    op.drop_column("tenants", "sovereignty_ring")
    op.drop_column("tenants", "home_region")
    op.drop_table("jwks_keys")
