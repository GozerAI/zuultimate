"""Vault Pydantic schemas for request/response validation."""

from pydantic import BaseModel, Field


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="Data to encrypt (AES-256-GCM)", examples=["sensitive-data-here"])
    label: str = Field(default="", description="Optional label for the encrypted blob", examples=["api-key-prod"])
    owner_id: str = Field(default="", description="Owner user ID for access control")


class EncryptResponse(BaseModel):
    blob_id: str = Field(..., description="UUID of the encrypted blob")
    label: str = Field(..., description="Label associated with the blob")


class DecryptRequest(BaseModel):
    blob_id: str = Field(..., description="UUID of the blob to decrypt")


class DecryptResponse(BaseModel):
    plaintext: str = Field(..., description="Decrypted plaintext data")


class TokenizeRequest(BaseModel):
    value: str = Field(..., description="Sensitive value to tokenize", examples=["4111-1111-1111-1111"])


class TokenizeResponse(BaseModel):
    token: str = Field(..., description="Opaque token replacing the original value")


class DetokenizeRequest(BaseModel):
    token: str


class DetokenizeResponse(BaseModel):
    value: str


class StoreSecretRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    value: str = Field(min_length=1, max_length=10000)
    category: str = Field(default="password", max_length=50)
    notes: str = Field(default="", max_length=1000)
