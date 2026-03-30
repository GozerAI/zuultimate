"""Pydantic schemas for access control API."""

from pydantic import BaseModel, Field


class AccessCheckRequest(BaseModel):
    user_id: str = Field(..., description="User UUID to check access for")
    resource: str = Field(..., description="Resource identifier", examples=["vault:secrets"])
    action: str = Field(..., description="Action to authorize", examples=["read"])


class AccessCheckResponse(BaseModel):
    allowed: bool = Field(..., description="Whether access is granted")
    reason: str = Field(default="", description="Explanation of the access decision")


class PolicySchema(BaseModel):
    name: str = Field(..., description="Policy display name", examples=["allow-vault-read"])
    effect: str = Field(..., description="Policy effect (allow/deny)")
    resource_pattern: str = Field(..., description="Resource glob pattern", examples=["vault:*"])
    action_pattern: str = Field(..., description="Action glob pattern", examples=["read"])
    priority: int = Field(default=0, description="Evaluation priority (higher wins)")
    role_id: str | None = Field(default=None, description="Optional role UUID to scope policy to")


class PolicyResponse(BaseModel):
    id: str = Field(..., description="Policy UUID")
    name: str = Field(..., description="Policy display name")
    effect: str = Field(..., description="Policy effect (allow/deny)")
    resource_pattern: str = Field(..., description="Resource glob pattern")
    action_pattern: str = Field(..., description="Action glob pattern")
    priority: int = Field(..., description="Evaluation priority")
    role_id: str | None = Field(default=None, description="Scoped role UUID")


class RoleAssignRequest(BaseModel):
    role_id: str = Field(..., description="Role UUID to assign")
    user_id: str = Field(..., description="User UUID to assign role to")
    assigned_by: str | None = Field(default=None, description="Admin user who made the assignment")


class RoleAssignResponse(BaseModel):
    id: str = Field(..., description="Assignment UUID")
    role_id: str = Field(..., description="Assigned role UUID")
    user_id: str = Field(..., description="User UUID")
    assigned_by: str | None = Field(default=None, description="Admin who made the assignment")
