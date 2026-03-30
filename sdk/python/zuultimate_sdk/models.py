"""Pydantic models for Zuultimate API responses."""

from pydantic import BaseModel


class TokenPair(BaseModel):
    """Represents an access/refresh token pair returned by login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class User(BaseModel):
    """Represents a user identity in the platform."""

    id: str
    email: str
    username: str
    display_name: str
    is_active: bool
    is_verified: bool
    tenant_id: str | None = None


class Tenant(BaseModel):
    """Represents a tenant organization."""

    id: str
    name: str
    slug: str
    is_active: bool
    plan: str
    status: str


class TenantProvisionResult(BaseModel):
    """Represents the result of provisioning a new tenant."""

    tenant_id: str
    user_id: str
    api_key: str
    plan: str
    entitlements: list[str]


class IntrospectResult(BaseModel):
    """Represents the result of token introspection."""

    active: bool
    sub: str | None = None
    username: str | None = None
    tenant_id: str | None = None
    token_type: str | None = None
    exp: int | None = None


class HealthStatus(BaseModel):
    """Represents the API health check response."""

    status: str
    version: str
    environment: str
