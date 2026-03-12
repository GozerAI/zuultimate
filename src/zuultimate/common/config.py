"""Zuultimate configuration via pydantic-settings."""

import warnings
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_DEFAULT_KEY = "insecure-dev-key-change-me"


class ZuulSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZUUL_")

    environment: str = "development"
    secret_key: str = _INSECURE_DEFAULT_KEY

    # Configurable crypto salts (override per deployment via env vars)
    vault_salt: str = "zuultimate-vault-v2"
    mfa_salt: str = "zuultimate-mfa-secret"
    password_vault_salt: str = "zuultimate-pw-vault"

    # SSO allowed redirect URI patterns
    sso_allowed_redirect_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Database URLs
    identity_db_url: str = "sqlite+aiosqlite:///./data/identity.db"
    credential_db_url: str = "sqlite+aiosqlite:///./data/credentials.db"
    session_db_url: str = "sqlite+aiosqlite:///./data/sessions.db"
    transaction_db_url: str = "sqlite+aiosqlite:///./data/transactions.db"
    audit_db_url: str = "sqlite+aiosqlite:///./data/audit.db"
    crm_db_url: str = "sqlite+aiosqlite:///./data/crm.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # AI Security
    redteam_passphrase: str = ""

    # API
    api_title: str = "Zuultimate"
    api_version: str = "1.0.0"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Limits
    max_audit_events: int = 10000
    threat_score_threshold: float = 0.3
    max_request_bytes: int = 1_048_576  # 1 MB

    # Auth / tokens
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7
    login_rate_limit: int = 10
    login_rate_window: int = 300  # seconds

    # Service-to-service auth (Vinzy → Zuultimate)
    service_token: str = ""


    def validate_for_production(self) -> None:
        """Raise if insecure defaults are used in non-development environments."""
        if self.environment != "development" and self.secret_key == _INSECURE_DEFAULT_KEY:
            raise RuntimeError(
                "ZUUL_SECRET_KEY must be set to a secure value in "
                f"'{self.environment}' environment. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        if self.secret_key == _INSECURE_DEFAULT_KEY:
            warnings.warn(
                "Using default insecure secret key — set ZUUL_SECRET_KEY for production",
                UserWarning,
                stacklevel=2,
            )


PLAN_ENTITLEMENTS: dict[str, list[str]] = {
    "starter": [
        "trendscope:basic",
        "shopforge:basic",
        "brandguard:basic",
        "taskpilot:basic",
        "sentinel:basic",
        "shandorcode:basic",
    ],
    "pro": [
        "trendscope:full",
        "nexus:basic",
        "shopforge:full",
        "brandguard:full",
        "taskpilot:full",
        "sentinel:full",
        "shandorcode:full",
    ],
    "business": [
        "trendscope:full",
        "nexus:full",
        "shopforge:full",
        "brandguard:full",
        "taskpilot:full",
        "sentinel:full",
        "shandorcode:full",
        "agentwerk:full",
        "white_label",
    ],
}


@lru_cache
def get_settings() -> ZuulSettings:
    settings = ZuulSettings()
    settings.validate_for_production()
    return settings
