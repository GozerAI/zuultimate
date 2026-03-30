"""Pydantic schemas for workforce endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field


# -- SSO / Federation --

class SSOInitiateRequest(BaseModel):
    provider_id: str = Field(..., description="SSO provider identifier")
    redirect_uri: str = Field(
        default="", description="Where to redirect after SSO"
    )


class SSOInitiateResponse(BaseModel):
    redirect_url: str
    state: str
    provider_id: str


class SSOCallbackRequest(BaseModel):
    provider_id: str
    saml_response: str = Field(default="", description="Base64-encoded SAML response")
    relay_state: str = Field(default="")


class SSOCallbackResponse(BaseModel):
    user_id: str
    email: str
    groups: list[str] = Field(default_factory=list)
    department: str = ""


# -- Workforce user info --

class WorkforceUserInfo(BaseModel):
    user_id: str
    username: str
    tenant_id: str | None = None
    namespace: str = "workforce"


# -- Device Posture --

class DevicePostureResponse(BaseModel):
    id: str
    device_id: str
    user_id: str
    tenant_id: str | None = None
    os_type: str = ""
    mdm_managed: bool = False
    disk_encrypted: bool = False
    posture_score: float = 0.0


# -- PoP Registration --

class PopRegisterRequest(BaseModel):
    pop_id: str = Field(..., min_length=1, max_length=64)
    pop_name: str = Field(..., min_length=1, max_length=255)
    region: str = Field(..., min_length=1, max_length=20)
    public_key: str = Field(..., min_length=1, description="PEM-encoded public key")


class PopResponse(BaseModel):
    id: str
    pop_id: str
    pop_name: str
    region: str
    status: str = "active"
    registered_at: datetime | None = None
    last_heartbeat: datetime | None = None


# -- JIT Access --

class JITRequestBody(BaseModel):
    scope: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1)
    tenant_id: str | None = None


class JITApproveBody(BaseModel):
    approver_id: str = Field(..., min_length=1)


class JITGrantResponse(BaseModel):
    id: str
    user_id: str
    scope: str
    reason: str
    approved_by: str | None = None
    status: str = "pending"
    requested_at: datetime | None = None
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    tenant_id: str | None = None


# -- Break Glass --

class BreakGlassInitiateRequest(BaseModel):
    reason: str = Field(..., min_length=1)
    tenant_id: str | None = None


class BreakGlassApproveBody(BaseModel):
    approver_id: str = Field(..., min_length=1)


class BreakGlassResponse(BaseModel):
    id: str
    user_id: str
    reason: str
    first_approver_id: str | None = None
    second_approver_id: str | None = None
    status: str = "pending"
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    audit_tag: str | None = None
    tenant_id: str | None = None


# -- Posture Webhook --

class PostureWebhookRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    compliance_status: str = Field(
        ..., description="compliant or non_compliant"
    )
    reason: str = Field(default="")
