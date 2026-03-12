"""DSAR Pydantic schemas for request/response validation."""

from pydantic import BaseModel, Field


class DSARSubmitRequest(BaseModel):
    tenant_id: str = Field(...)
    subject_id: str = Field(...)
    request_type: str = Field(..., pattern=r"^(access|deletion|portability|correction|restriction)$")


class DSARAdvanceRequest(BaseModel):
    status: str = Field(..., pattern=r"^(validated|processing|fulfilled|rejected)$")


class DSARResponse(BaseModel):
    id: str
    tenant_id: str
    subject_id: str
    request_type: str
    status: str
    received_at: str
    due_at: str
    fulfilled_at: str | None = None
    evidence_trail: list[dict]
    is_overdue: bool = False
