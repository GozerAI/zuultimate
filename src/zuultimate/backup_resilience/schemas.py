"""Backup & resilience Pydantic schemas."""

from pydantic import BaseModel, Field


class SnapshotCreate(BaseModel):
    name: str = Field(..., description="Snapshot display name", examples=["daily-2026-02-21"])
    source: str = Field(..., description="Data source to snapshot", examples=["identity_db"])


class SnapshotResponse(BaseModel):
    id: str = Field(..., description="Snapshot UUID")
    name: str = Field(..., description="Snapshot display name")
    source: str = Field(..., description="Data source that was snapshotted")
    checksum: str = Field(..., description="SHA-256 checksum of snapshot data")
    status: str = Field(..., description="Snapshot status (completed/failed)")


class RestoreRequest(BaseModel):
    snapshot_id: str = Field(..., description="Snapshot UUID to restore from")
    target: str = Field(..., description="Restore target", examples=["identity_db"])


class RestoreResponse(BaseModel):
    id: str = Field(..., description="Restore job UUID")
    snapshot_id: str = Field(..., description="Source snapshot UUID")
    target: str = Field(..., description="Restore target")
    status: str = Field(..., description="Job status (completed/failed)")


class IntegrityCheckRequest(BaseModel):
    target: str = Field(..., description="Target to check integrity of", examples=["identity_db"])


class IntegrityCheckResponse(BaseModel):
    id: str = Field(..., description="Integrity check UUID")
    target: str = Field(..., description="Target that was checked")
    passed: bool | None = Field(default=None, description="Whether integrity check passed")
    status: str = Field(..., description="Check status (completed/failed)")
