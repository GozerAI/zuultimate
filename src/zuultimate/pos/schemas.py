"""POS Pydantic schemas."""

from pydantic import BaseModel, Field


class TerminalCreate(BaseModel):
    name: str = Field(..., description="Terminal display name", examples=["Register-1"])
    location: str = Field(default="", description="Physical location", examples=["Floor 2"])
    device_type: str = Field(default="", description="Device hardware type", examples=["kiosk"])


class TerminalResponse(BaseModel):
    id: str = Field(..., description="Terminal UUID")
    name: str = Field(..., description="Terminal display name")
    location: str = Field(..., description="Physical location")
    is_active: bool = Field(..., description="Whether the terminal is active")
    device_type: str = Field(..., description="Device hardware type")


class TransactionCreate(BaseModel):
    terminal_id: str = Field(..., description="Terminal UUID to process through")
    amount: float = Field(..., description="Transaction amount", examples=[49.99])
    currency: str = Field(default="USD", description="ISO 4217 currency code")


class TransactionResponse(BaseModel):
    id: str = Field(..., description="Transaction UUID")
    terminal_id: str = Field(..., description="Terminal that processed the transaction")
    amount: float = Field(..., description="Transaction amount")
    currency: str = Field(..., description="ISO 4217 currency code")
    status: str = Field(..., description="Transaction status (completed/pending/failed)")
    reference: str = Field(..., description="Unique transaction reference (TXN-<hex>)")


class FraudAlertResponse(BaseModel):
    id: str = Field(..., description="Alert UUID")
    transaction_id: str = Field(..., description="Flagged transaction UUID")
    alert_type: str = Field(..., description="Alert classification")
    severity: str = Field(..., description="Severity level (low/medium/high/critical)")
    detail: str = Field(default="", description="Human-readable alert detail")
    resolved: bool = Field(default=False, description="Whether the alert has been resolved")
