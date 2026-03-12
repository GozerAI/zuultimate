"""Shared Pydantic schemas for Zuultimate API."""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Pagination(BaseModel):
    page: int = Field(1, ge=1, description="Current page number")
    page_size: int = Field(50, ge=1, le=200, description="Items per page")
    total: int = Field(default=0, description="Total number of items")
    total_pages: int = Field(default=0, description="Total number of pages")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T] = Field(default_factory=list, description="Page of results")
    pagination: Pagination = Field(default_factory=Pagination, description="Pagination metadata")


class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error message")
    code: str = Field(default="ZUUL_ERROR", description="Machine-readable error code")
    detail: str | None = Field(default=None, description="Additional error context")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Overall health status")
    version: str = Field(default="0.1.0", description="API version")
    environment: str = Field(default="development", description="Current environment")
    timestamp: datetime | None = Field(default=None, description="Health check timestamp")
    checks: dict[str, str] | None = Field(default=None, description="Per-subsystem check results")


# Standard OpenAPI error response documentation
STANDARD_ERRORS: dict[int, dict] = {
    401: {"model": ErrorResponse, "description": "Authentication required or token invalid"},
    403: {"model": ErrorResponse, "description": "Insufficient permissions"},
    404: {"model": ErrorResponse, "description": "Resource not found"},
    422: {"model": ErrorResponse, "description": "Validation error"},
    429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
}
