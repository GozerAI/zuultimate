"""CRM Pydantic schemas."""

from pydantic import BaseModel, Field


class CRMConfigCreate(BaseModel):
    provider: str = Field(..., description="CRM provider name", examples=["salesforce"])
    api_url: str = Field(default="", description="Provider API base URL")


class CRMConfigResponse(BaseModel):
    id: str = Field(..., description="Config UUID")
    provider: str = Field(..., description="CRM provider name")
    api_url: str = Field(..., description="Provider API base URL")
    is_active: bool = Field(..., description="Whether this config is active")


class SyncStartRequest(BaseModel):
    config_id: str = Field(..., description="CRM config UUID to sync from")


class SyncJobResponse(BaseModel):
    id: str = Field(..., description="Sync job UUID")
    config_id: str = Field(..., description="CRM config UUID")
    status: str = Field(..., description="Job status (pending/running/completed/failed)")
    records_synced: int = Field(..., description="Number of records synced so far")
