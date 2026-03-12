"""v1.0.0 hardening: ForeignKeys, indexes, new tables, tenant columns, security_events PK change

Adds all missing ForeignKey constraints, database indexes, new tables
(tenants, sso_providers, email_verification_tokens, settlement_batches,
user_secrets, webhook_configs, webhook_deliveries, idempotency_records),
tenant_id columns, missing columns on encrypted_blobs, and changes
security_events.id from Integer to String(36) UUID.

Revision ID: v1_0_0_hardening
Revises: d28ee951fea7
Create Date: 2026-02-20 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "v1_0_0_hardening"
down_revision: Union[str, None] = "d28ee951fea7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(name: str) -> bool:
    """Check if a table already exists (handles create_all before migrate)."""
    from sqlalchemy import inspect
    conn = op.get_bind()
    return name in inspect(conn).get_table_names()


def _column_exists(table: str, column: str) -> bool:
    """Check if a column already exists on a table."""
    from sqlalchemy import inspect
    conn = op.get_bind()
    cols = [c["name"] for c in inspect(conn).get_columns(table)]
    return column in cols


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # 1. Create new tables that other tables may reference               #
    # ------------------------------------------------------------------ #

    # -- tenants (must exist before FK columns reference it) --
    if not _table_exists("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("slug", sa.String(length=100), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("slug"),
        )

    # -- sso_providers --
    if not _table_exists("sso_providers"):
        op.create_table(
            "sso_providers",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("protocol", sa.String(length=20), nullable=False),
            sa.Column("issuer_url", sa.String(length=500), nullable=False),
            sa.Column("client_id", sa.String(length=255), nullable=False),
            sa.Column("client_secret_encrypted", sa.Text(), nullable=True),
            sa.Column("metadata_url", sa.String(length=500), nullable=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_sso_providers_tenant_id", "sso_providers", ["tenant_id"])

    # -- email_verification_tokens --
    if not _table_exists("email_verification_tokens"):
        op.create_table(
            "email_verification_tokens",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column(
                "user_id",
                sa.String(length=36),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("token_hash", sa.String(length=255), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token_hash"),
        )
        op.create_index(
            "ix_email_verification_tokens_user_id",
            "email_verification_tokens",
            ["user_id"],
        )

    # -- settlement_batches --
    if not _table_exists("settlement_batches"):
        op.create_table(
            "settlement_batches",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column(
                "terminal_id",
                sa.String(length=36),
                sa.ForeignKey("terminals.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("transaction_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("total_amount", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("currency", sa.String(length=3), nullable=False, server_default=sa.text("'USD'")),
            sa.Column("status", sa.String(length=50), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("reference", sa.String(length=255), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_settlement_batches_terminal_id", "settlement_batches", ["terminal_id"]
        )

    # -- user_secrets --
    if not _table_exists("user_secrets"):
        op.create_table(
            "user_secrets",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
            sa.Column("nonce", sa.LargeBinary(), nullable=False),
            sa.Column("tag", sa.LargeBinary(), nullable=False),
            sa.Column("category", sa.String(length=50), nullable=False, server_default=sa.text("'password'")),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_user_secrets_user_id", "user_secrets", ["user_id"])

    # -- webhook_configs --
    if not _table_exists("webhook_configs"):
        op.create_table(
            "webhook_configs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("url", sa.String(length=500), nullable=False),
            sa.Column("events_filter", sa.String(length=500), nullable=False, server_default=sa.text("'*'")),
            sa.Column("secret", sa.String(length=255), nullable=False, server_default=sa.text("''")),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("description", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    # -- webhook_deliveries --
    if not _table_exists("webhook_deliveries"):
        op.create_table(
            "webhook_deliveries",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("webhook_id", sa.String(length=36), nullable=False),
            sa.Column("event_type", sa.String(length=100), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("response_code", sa.Integer(), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("payload", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    # -- idempotency_records --
    if not _table_exists("idempotency_records"):
        op.create_table(
            "idempotency_records",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("idempotency_key", sa.String(length=255), nullable=False),
            sa.Column("endpoint", sa.String(length=500), nullable=False),
            sa.Column("response_status", sa.Integer(), nullable=False),
            sa.Column("response_body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("idempotency_key"),
        )

    # ------------------------------------------------------------------ #
    # 2. Add missing columns on existing tables                          #
    # ------------------------------------------------------------------ #

    # -- users: add tenant_id FK column --
    if not _column_exists("users", "tenant_id"):
        with op.batch_alter_table("users") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "tenant_id",
                    sa.String(length=36),
                    nullable=True,
                )
            )
            batch_op.create_foreign_key(
                "fk_users_tenant_id", "tenants", ["tenant_id"], ["id"], ondelete="SET NULL"
            )
            batch_op.create_index("ix_users_tenant_id", ["tenant_id"])

    # -- terminals: add tenant_id column --
    if not _column_exists("terminals", "tenant_id"):
        with op.batch_alter_table("terminals") as batch_op:
            batch_op.add_column(
                sa.Column("tenant_id", sa.String(length=36), nullable=True)
            )
            batch_op.create_index("ix_terminals_tenant_id", ["tenant_id"])

    # -- snapshots: add tenant_id column --
    if not _column_exists("snapshots", "tenant_id"):
        with op.batch_alter_table("snapshots") as batch_op:
            batch_op.add_column(
                sa.Column("tenant_id", sa.String(length=36), nullable=True)
            )
            batch_op.create_index("ix_snapshots_tenant_id", ["tenant_id"])

    # -- crm_configs: add tenant_id column --
    if not _column_exists("crm_configs", "tenant_id"):
        with op.batch_alter_table("crm_configs") as batch_op:
            batch_op.add_column(
                sa.Column("tenant_id", sa.String(length=36), nullable=True)
            )
            batch_op.create_index("ix_crm_configs_tenant_id", ["tenant_id"])

    # -- encrypted_blobs: add rotation_count and last_rotated --
    if not _column_exists("encrypted_blobs", "rotation_count"):
        with op.batch_alter_table("encrypted_blobs") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "rotation_count",
                    sa.Integer(),
                    nullable=False,
                    server_default=sa.text("0"),
                )
            )
            batch_op.add_column(
                sa.Column("last_rotated", sa.DateTime(timezone=True), nullable=True)
            )

    # ------------------------------------------------------------------ #
    # 3. Rebuild security_events: Integer PK -> String(36) UUID PK       #
    #    SQLite cannot ALTER COLUMN type, so we recreate via batch mode.  #
    # ------------------------------------------------------------------ #
    with op.batch_alter_table(
        "security_events",
        recreate="always",
        copy_from=sa.Table(
            "security_events",
            sa.MetaData(),
            sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
            sa.Column("event_type", sa.String(length=50), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("agent_code", sa.String(length=20), nullable=False),
            sa.Column("tool_name", sa.String(length=100), nullable=False),
            sa.Column("detail", sa.Text(), nullable=False),
            sa.Column("threat_score", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        ),
    ) as batch_op:
        batch_op.alter_column(
            "id",
            existing_type=sa.Integer(),
            type_=sa.String(length=36),
            existing_nullable=False,
            autoincrement=False,
        )
        # Re-create the agent_code index (event_type and severity indexes
        # already exist from the initial migration and are preserved)
        batch_op.create_index("ix_security_events_agent_code", ["agent_code"])

    # ------------------------------------------------------------------ #
    # 4. Add ForeignKey constraints on existing tables via batch mode     #
    #    SQLite requires table recreation to add FK constraints.          #
    # ------------------------------------------------------------------ #

    # -- credentials.user_id -> users.id --
    with op.batch_alter_table("credentials") as batch_op:
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_credentials_user_id", "users", ["user_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.create_index("ix_credentials_user_id", ["user_id"])

    # -- mfa_devices.user_id -> users.id --
    with op.batch_alter_table("mfa_devices") as batch_op:
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_mfa_devices_user_id", "users", ["user_id"], ["id"], ondelete="CASCADE"
        )
        batch_op.create_index("ix_mfa_devices_user_id", ["user_id"])

    # -- user_sessions.user_id -> users.id --
    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_user_sessions_user_id",
            "users",
            ["user_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_user_sessions_user_id", ["user_id"])
        batch_op.create_index(
            "ix_user_sessions_access_token_hash", ["access_token_hash"]
        )

    # -- policies.role_id -> roles.id --
    with op.batch_alter_table("policies") as batch_op:
        batch_op.create_foreign_key(
            "fk_policies_role_id",
            "roles",
            ["role_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_policies_role_id", ["role_id"])

    # -- role_assignments.role_id -> roles.id --
    with op.batch_alter_table("role_assignments") as batch_op:
        batch_op.alter_column(
            "role_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_role_assignments_role_id",
            "roles",
            ["role_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_role_assignments_role_id", ["role_id"])
        batch_op.create_index("ix_role_assignments_user_id", ["user_id"])

    # -- restore_jobs.snapshot_id -> snapshots.id --
    with op.batch_alter_table("restore_jobs") as batch_op:
        batch_op.alter_column(
            "snapshot_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_restore_jobs_snapshot_id",
            "snapshots",
            ["snapshot_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_restore_jobs_snapshot_id", ["snapshot_id"])

    # -- transactions.terminal_id -> terminals.id --
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.alter_column(
            "terminal_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_transactions_terminal_id",
            "terminals",
            ["terminal_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_transactions_terminal_id", ["terminal_id"])

    # -- fraud_alerts.transaction_id -> transactions.id --
    with op.batch_alter_table("fraud_alerts") as batch_op:
        batch_op.alter_column(
            "transaction_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_fraud_alerts_transaction_id",
            "transactions",
            ["transaction_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_fraud_alerts_transaction_id", ["transaction_id"])
        batch_op.create_index("ix_fraud_alerts_resolved", ["resolved"])

    # -- sync_jobs.config_id -> crm_configs.id --
    with op.batch_alter_table("sync_jobs") as batch_op:
        batch_op.alter_column(
            "config_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_sync_jobs_config_id",
            "crm_configs",
            ["config_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_sync_jobs_config_id", ["config_id"])

    # -- field_mappings.config_id -> crm_configs.id --
    with op.batch_alter_table("field_mappings") as batch_op:
        batch_op.alter_column(
            "config_id",
            existing_type=sa.String(length=255),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
        batch_op.create_foreign_key(
            "fk_field_mappings_config_id",
            "crm_configs",
            ["config_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index("ix_field_mappings_config_id", ["config_id"])

    # ------------------------------------------------------------------ #
    # 5. Add remaining indexes on existing tables (no FK involved)       #
    # ------------------------------------------------------------------ #

    # -- audit_entries.user_id --
    op.create_index("ix_audit_entries_user_id", "audit_entries", ["user_id"])

    # -- permissions.resource, permissions.action --
    op.create_index("ix_permissions_resource", "permissions", ["resource"])
    op.create_index("ix_permissions_action", "permissions", ["action"])

    # -- encrypted_blobs.owner_id --
    op.create_index("ix_encrypted_blobs_owner_id", "encrypted_blobs", ["owner_id"])


def downgrade() -> None:
    # ------------------------------------------------------------------ #
    # Reverse step 5: drop standalone indexes                            #
    # ------------------------------------------------------------------ #
    op.drop_index("ix_encrypted_blobs_owner_id", table_name="encrypted_blobs")
    op.drop_index("ix_permissions_action", table_name="permissions")
    op.drop_index("ix_permissions_resource", table_name="permissions")
    op.drop_index("ix_audit_entries_user_id", table_name="audit_entries")

    # ------------------------------------------------------------------ #
    # Reverse step 4: remove FKs and indexes from existing tables        #
    # ------------------------------------------------------------------ #

    # -- field_mappings --
    with op.batch_alter_table("field_mappings") as batch_op:
        batch_op.drop_index("ix_field_mappings_config_id")
        batch_op.drop_constraint("fk_field_mappings_config_id", type_="foreignkey")
        batch_op.alter_column(
            "config_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- sync_jobs --
    with op.batch_alter_table("sync_jobs") as batch_op:
        batch_op.drop_index("ix_sync_jobs_config_id")
        batch_op.drop_constraint("fk_sync_jobs_config_id", type_="foreignkey")
        batch_op.alter_column(
            "config_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- fraud_alerts --
    with op.batch_alter_table("fraud_alerts") as batch_op:
        batch_op.drop_index("ix_fraud_alerts_resolved")
        batch_op.drop_index("ix_fraud_alerts_transaction_id")
        batch_op.drop_constraint("fk_fraud_alerts_transaction_id", type_="foreignkey")
        batch_op.alter_column(
            "transaction_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- transactions --
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_index("ix_transactions_terminal_id")
        batch_op.drop_constraint("fk_transactions_terminal_id", type_="foreignkey")
        batch_op.alter_column(
            "terminal_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- restore_jobs --
    with op.batch_alter_table("restore_jobs") as batch_op:
        batch_op.drop_index("ix_restore_jobs_snapshot_id")
        batch_op.drop_constraint("fk_restore_jobs_snapshot_id", type_="foreignkey")
        batch_op.alter_column(
            "snapshot_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- role_assignments --
    with op.batch_alter_table("role_assignments") as batch_op:
        batch_op.drop_index("ix_role_assignments_user_id")
        batch_op.drop_index("ix_role_assignments_role_id")
        batch_op.drop_constraint("fk_role_assignments_role_id", type_="foreignkey")
        batch_op.alter_column(
            "role_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- policies --
    with op.batch_alter_table("policies") as batch_op:
        batch_op.drop_index("ix_policies_role_id")
        batch_op.drop_constraint("fk_policies_role_id", type_="foreignkey")

    # -- user_sessions --
    with op.batch_alter_table("user_sessions") as batch_op:
        batch_op.drop_index("ix_user_sessions_access_token_hash")
        batch_op.drop_index("ix_user_sessions_user_id")
        batch_op.drop_constraint("fk_user_sessions_user_id", type_="foreignkey")
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- mfa_devices --
    with op.batch_alter_table("mfa_devices") as batch_op:
        batch_op.drop_index("ix_mfa_devices_user_id")
        batch_op.drop_constraint("fk_mfa_devices_user_id", type_="foreignkey")
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # -- credentials --
    with op.batch_alter_table("credentials") as batch_op:
        batch_op.drop_index("ix_credentials_user_id")
        batch_op.drop_constraint("fk_credentials_user_id", type_="foreignkey")
        batch_op.alter_column(
            "user_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=255),
            existing_nullable=False,
        )

    # ------------------------------------------------------------------ #
    # Reverse step 3: revert security_events PK back to Integer          #
    # ------------------------------------------------------------------ #
    with op.batch_alter_table(
        "security_events",
        recreate="always",
        copy_from=sa.Table(
            "security_events",
            sa.MetaData(),
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("event_type", sa.String(length=50), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("agent_code", sa.String(length=20), nullable=False),
            sa.Column("tool_name", sa.String(length=100), nullable=False),
            sa.Column("detail", sa.Text(), nullable=False),
            sa.Column("threat_score", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        ),
    ) as batch_op:
        batch_op.alter_column(
            "id",
            existing_type=sa.String(length=36),
            type_=sa.Integer(),
            existing_nullable=False,
            autoincrement=True,
        )
        batch_op.drop_index("ix_security_events_agent_code")

    # ------------------------------------------------------------------ #
    # Reverse step 2: remove added columns from existing tables          #
    # ------------------------------------------------------------------ #

    # -- encrypted_blobs: drop rotation_count and last_rotated --
    with op.batch_alter_table("encrypted_blobs") as batch_op:
        batch_op.drop_column("last_rotated")
        batch_op.drop_column("rotation_count")

    # -- crm_configs: drop tenant_id --
    with op.batch_alter_table("crm_configs") as batch_op:
        batch_op.drop_index("ix_crm_configs_tenant_id")
        batch_op.drop_column("tenant_id")

    # -- snapshots: drop tenant_id --
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_index("ix_snapshots_tenant_id")
        batch_op.drop_column("tenant_id")

    # -- terminals: drop tenant_id --
    with op.batch_alter_table("terminals") as batch_op:
        batch_op.drop_index("ix_terminals_tenant_id")
        batch_op.drop_column("tenant_id")

    # -- users: drop tenant_id --
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_tenant_id")
        batch_op.drop_constraint("fk_users_tenant_id", type_="foreignkey")
        batch_op.drop_column("tenant_id")

    # ------------------------------------------------------------------ #
    # Reverse step 1: drop new tables                                    #
    # ------------------------------------------------------------------ #
    op.drop_table("idempotency_records")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_configs")
    op.drop_table("user_secrets")
    op.drop_index("ix_settlement_batches_terminal_id", table_name="settlement_batches")
    op.drop_table("settlement_batches")
    op.drop_index(
        "ix_email_verification_tokens_user_id",
        table_name="email_verification_tokens",
    )
    op.drop_table("email_verification_tokens")
    op.drop_index("ix_sso_providers_tenant_id", table_name="sso_providers")
    op.drop_table("sso_providers")
    op.drop_table("tenants")
