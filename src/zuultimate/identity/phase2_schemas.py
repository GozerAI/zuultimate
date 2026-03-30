"""Phase 2 Identity Pydantic schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


# ── IdentityToken ────────────────────────────────────────────────────────────


class IdentityTokenResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    tenant_id: str | None = None
    display_name: str = ""
    parent_token_id: str | None = None
    is_active: bool = True
    created_at: datetime | None = None


class ResolveIdentityRequest(BaseModel):
    """Resolve current auth credentials to an IdentityToken."""

    entity_type: str = Field(
        default="user", description="Entity type: user, agent, service",
    )
    entity_id: str | None = Field(
        default=None,
        description="Override entity_id (for agent/service registration). "
        "If not provided, uses authenticated user_id.",
    )
    display_name: str = Field(default="", description="Display name for the identity")
    metadata: dict = Field(default_factory=dict, description="Entity-specific metadata")


# ── CapabilityToken ──────────────────────────────────────────────────────────


class GrantCapabilityRequest(BaseModel):
    grantee_identity_id: str = Field(..., description="IdentityToken ID of the grantee")
    capability: str = Field(..., description="Capability string, e.g. 'vault:encrypt'")
    resource_scope: str = Field(default="*", description="Glob pattern for resource scope")
    constraints: dict = Field(default_factory=dict, description="Additional constraints")
    delegatable: bool = Field(default=False, description="Can the grantee re-delegate?")
    ttl_seconds: int = Field(
        default=3600, ge=60, le=86400,
        description="Time-to-live in seconds (1min–24h)",
    )


class DelegateCapabilityRequest(BaseModel):
    grantee_identity_id: str = Field(..., description="IdentityToken ID of the delegate")
    resource_scope: str | None = Field(
        default=None,
        description="Attenuated scope (must be subset of parent). None = same scope.",
    )
    ttl_seconds: int = Field(
        default=3600, ge=60, le=86400,
        description="TTL for delegated capability (cannot exceed parent)",
    )


class CapabilityTokenResponse(BaseModel):
    id: str
    identity_token_id: str
    capability: str
    resource_scope: str
    constraints: dict = {}
    granted_by: str | None = None
    parent_capability_id: str | None = None
    delegatable: bool = False
    expires_at: datetime
    revoked_at: datetime | None = None
    created_at: datetime | None = None


class RevokeCapabilityRequest(BaseModel):
    reason: str = Field(default="", description="Reason for revocation")


# ── DataShape ────────────────────────────────────────────────────────────────


class CreateDataShapeRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    sensitivity: str = Field(
        default="internal",
        description="public | internal | confidential | restricted",
    )
    schema_definition: dict = Field(default_factory=dict, description="JSON Schema")
    retention_days: int = Field(default=365, ge=1)
    pii_fields: list[str] = Field(default_factory=list, description="Field paths containing PII")
    tenant_id: str | None = Field(default=None, description="Tenant scope (null = system-wide)")


class DataShapeResponse(BaseModel):
    id: str
    name: str
    tenant_id: str | None = None
    sensitivity: str = "internal"
    retention_days: int = 365
    pii_fields: list[str] = []
    created_at: datetime | None = None


# ── PolicyDecision ───────────────────────────────────────────────────────────


class EnforceRequest(BaseModel):
    resource: str = Field(..., description="Resource being accessed")
    action: str = Field(..., description="Action being performed")
    data_shape_name: str | None = Field(
        default=None, description="DataShape name for field-level filtering",
    )


class PolicyDecisionResponse(BaseModel):
    id: str
    decision: str  # "allow" | "deny" | "allow_filtered"
    reason: str = ""
    filtered_fields: list[str] = []
    latency_ms: int = 0
    evaluated_at: datetime
