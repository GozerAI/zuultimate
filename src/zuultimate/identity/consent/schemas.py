"""Consent request and response schemas."""

from pydantic import BaseModel, Field


class ConsentGrantRequest(BaseModel):
    tenant_id: str = Field(..., description="Opaque tenant identifier")
    subject_id: str = Field(..., description="Opaque subject identifier")
    purpose: str = Field(..., pattern=r"^(marketing|analytics|essential|third_party_share)$")
    version: str = Field(default="1.0", description="Consent policy version")
    channel: str = Field(default="api", description="Collection channel (web/mobile/api)")
    ip_hash: str = Field(default="", description="Hashed IP address")
    evidence: dict | None = Field(default=None, description="UI interaction evidence")


class ConsentRevokeRequest(BaseModel):
    tenant_id: str = Field(...)
    subject_id: str = Field(...)
    purpose: str = Field(..., pattern=r"^(marketing|analytics|essential|third_party_share)$")


class ConsentResponse(BaseModel):
    id: str
    tenant_id: str
    subject_id: str
    purpose: str
    granted: bool
    granted_at: str | None = None
    revoked_at: str | None = None
    version: str
    channel: str


class ConsentHistoryResponse(BaseModel):
    records: list[ConsentResponse]
