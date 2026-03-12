"""Identity Pydantic schemas."""

import re

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email address", examples=["user@example.com"])
    username: str = Field(min_length=3, max_length=100, description="Unique username", examples=["jdoe"])
    password: str = Field(min_length=8, description="Password (min 8 chars, must include letter and digit)", examples=["Secret1234"])
    display_name: str = Field(default="", description="Optional display name", examples=["Jane Doe"])

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r"[a-zA-Z]", v):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username or email", examples=["jdoe"])
    password: str = Field(..., description="Account password", examples=["Secret1234"])


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token from login response")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(default="", description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    expires_in: int = Field(default=3600, description="Token lifetime in seconds")


class UserResponse(BaseModel):
    id: str = Field(..., description="User UUID", examples=["550e8400-e29b-41d4-a716-446655440000"])
    email: str = Field(..., description="User email address", examples=["user@example.com"])
    username: str = Field(..., description="Unique username", examples=["jdoe"])
    display_name: str = Field(..., description="Display name", examples=["Jane Doe"])
    is_active: bool = Field(..., description="Whether the account is active")
    is_verified: bool = Field(..., description="Whether the email is verified")
    tenant_id: str | None = Field(default=None, description="Tenant ID if multi-tenant")


class MFASetupResponse(BaseModel):
    device_id: str = Field(..., description="MFA device identifier")
    secret: str = Field(..., description="TOTP secret (base32-encoded)")
    provisioning_uri: str = Field(..., description="otpauth:// URI for authenticator apps")


class MFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, description="6-digit TOTP code", examples=["123456"])


class MFAChallengeRequest(BaseModel):
    mfa_token: str = Field(..., description="Temporary MFA challenge token from login")
    code: str = Field(min_length=6, max_length=6, description="6-digit TOTP code", examples=["123456"])


class EmailVerifyRequest(BaseModel):
    token: str = Field(min_length=1, description="Email verification token")


class EmailVerificationResponse(BaseModel):
    user_id: str = Field(..., description="User UUID")
    email: str = Field(..., description="Verified email address")
    verified: bool = Field(..., description="Whether verification succeeded")


class VerificationTokenResponse(BaseModel):
    user_id: str = Field(..., description="User UUID")
    email: str = Field(..., description="Email address to verify")
    token: str = Field(..., description="Verification token")
    expires_at: str = Field(..., description="Token expiry timestamp (ISO 8601)")


class SSOProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255, description="Provider display name", examples=["Okta Production"])
    protocol: str = Field(pattern=r"^(oidc|saml)$", description="SSO protocol ('oidc' or 'saml')", examples=["oidc"])
    issuer_url: str = Field(min_length=1, max_length=500, description="Identity provider issuer URL", examples=["https://accounts.google.com"])
    client_id: str = Field(min_length=1, max_length=255, description="OAuth2 client ID", examples=["my-client-id"])
    client_secret: str = Field(default="", description="OAuth2 client secret")
    metadata_url: str = Field(default="", description="OIDC discovery or SAML metadata URL")
    tenant_id: str | None = Field(default=None, description="Scope provider to a specific tenant")


class SSOProviderResponse(BaseModel):
    id: str = Field(..., description="Provider UUID")
    name: str = Field(..., description="Provider display name")
    protocol: str = Field(..., description="SSO protocol ('oidc' or 'saml')")
    issuer_url: str = Field(..., description="Identity provider issuer URL")
    client_id: str = Field(..., description="OAuth2 client ID")
    metadata_url: str | None = Field(default=None, description="Discovery/metadata URL")
    tenant_id: str | None = Field(default=None, description="Associated tenant ID")
    is_active: bool = Field(..., description="Whether provider is active")


class SSOLoginInitResponse(BaseModel):
    redirect_url: str = Field(..., description="URL to redirect the user to for authentication")
    state: str = Field(..., description="CSRF state parameter")
    provider_id: str = Field(..., description="SSO provider UUID")


class SSOCallbackRequest(BaseModel):
    provider_id: str = Field(..., description="SSO provider UUID")
    code: str = Field(..., description="Authorization code from IdP")
    state: str = Field(..., description="CSRF state parameter to verify")


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255, description="Tenant display name", examples=["Acme Corp"])
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$", description="URL-safe slug (lowercase, hyphens)", examples=["acme-corp"])


class TenantResponse(BaseModel):
    id: str = Field(..., description="Tenant UUID")
    name: str = Field(..., description="Tenant display name")
    slug: str = Field(..., description="URL-safe tenant slug")
    is_active: bool = Field(..., description="Whether the tenant is active")
    plan: str = Field(default="starter", description="Subscription plan")
    status: str = Field(default="active", description="Tenant status")


class TenantProvisionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255, description="Tenant display name", examples=["Acme Corp"])
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$", description="URL-safe slug", examples=["acme-corp"])
    owner_email: str = Field(..., description="Owner user email", examples=["admin@acme.com"])
    owner_username: str = Field(min_length=3, max_length=100, description="Owner username", examples=["acme-admin"])
    owner_password: str = Field(min_length=8, description="Owner password", examples=["Secret1234"])
    plan: str = Field(default="starter", pattern=r"^(starter|pro|business)$", description="Subscription plan")
    stripe_customer_id: str | None = Field(default=None, description="Stripe customer ID")
    stripe_subscription_id: str | None = Field(default=None, description="Stripe subscription ID")

    @field_validator("owner_email")
    @classmethod
    def validate_owner_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()


class TenantProvisionResponse(BaseModel):
    tenant_id: str = Field(..., description="Created tenant UUID")
    user_id: str = Field(..., description="Created owner user UUID")
    api_key: str = Field(..., description="Plaintext API key (shown only once)")
    plan: str = Field(..., description="Subscription plan")
    entitlements: list[str] = Field(default_factory=list, description="Granted feature entitlements")


class AuthValidateResponse(BaseModel):
    user_id: str | None = Field(default=None, description="User UUID (None for API key auth)")
    username: str = Field(..., description="Username or API key name")
    tenant_id: str | None = Field(default=None, description="Tenant UUID")
    plan: str = Field(default="starter", description="Tenant subscription plan")
    entitlements: list[str] = Field(default_factory=list, description="Feature entitlements")
