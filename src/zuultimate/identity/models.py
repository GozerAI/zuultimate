"""Identity SQLAlchemy models."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    generate_uuid,
)


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    plan: Mapped[str] = mapped_column(String(50), default="starter")  # starter | pro | business
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | suspended | cancelled
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    default_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    pii_fields_json: Mapped[str] = mapped_column(Text, default="[]")
    home_region: Mapped[str] = mapped_column(String(20), default="us")
    sovereignty_ring: Mapped[str] = mapped_column(String(20), default="us")
    pii_allowed_regions: Mapped[str] = mapped_column(Text, default='["us"]')
    namespace: Mapped[str] = mapped_column(String(20), default="consumer")


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(255), default="Default")
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class User(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True,
    )


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    hashed_value: Mapped[str] = mapped_column(Text, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=True)


class MFADevice(Base, TimestampMixin):
    __tablename__ = "mfa_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    device_type: Mapped[str] = mapped_column(String(50), nullable=False)  # totp/webauthn/sms
    device_name: Mapped[str] = mapped_column(String(255), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)


class SSOProvider(Base, TimestampMixin):
    __tablename__ = "sso_providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)  # oidc or saml
    issuer_url: Mapped[str] = mapped_column(String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class EmailVerificationToken(Base, TimestampMixin):
    __tablename__ = "email_verification_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthEvent(Base):
    """Structured auth event for audit trail -- all identifiers are hashed."""

    __tablename__ = "auth_events"
    __table_args__ = (
        # Composite index for time-range + type queries (audit log archival, reporting)
        Index("ix_auth_events_type_created", "event_type", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    tenant_id_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_hash: Mapped[str] = mapped_column(String(64))
    user_agent_hash: Mapped[str] = mapped_column(String(16))
    username_hash: Mapped[str | None] = mapped_column(String(16), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class UserSession(Base, TimestampMixin):
    __tablename__ = "user_sessions"
    __table_args__ = (
        # Composite index for fast session lookup by user + expiry + active status
        Index("ix_user_sessions_user_active_expires", "user_id", "expires_at", "is_consumed"),
        # Partial index on active (unconsumed) sessions only
        Index(
            "ix_user_sessions_active_only",
            "user_id",
            "expires_at",
            sqlite_where=text("is_consumed = 0"),
            postgresql_where=text("is_consumed = false"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    access_token_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    token_family: Mapped[str] = mapped_column(String(36), nullable=False, default=generate_uuid, index=True)
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnCredential(Base, TimestampMixin):
    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)  # base64-encoded
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str] = mapped_column(String(255), default="")  # comma-separated
    aaguid: Mapped[str] = mapped_column(String(36), default="")
    credential_name: Mapped[str] = mapped_column(String(255), default="Default Passkey")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
