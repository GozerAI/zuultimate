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

    # Database pool
    db_pool_size: int = 10
    db_max_overflow: int = 20

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

    # OIDC provider discovery URL (optional global default)
    oidc_provider_url: str = ""

    # Service-to-service auth (Vinzy → Zuultimate)
    service_token: str = ""

    # WebAuthn / Passkeys
    webauthn_rp_id: str = "localhost"
    webauthn_origin: str = "http://localhost:8000"

    # Multi-region
    region: str = "us"
    sovereignty_ring: str = "us"


    def validate_for_production(self) -> None:
        """Raise if insecure defaults are used in non-development environments."""
        if self.environment != "development" and self.secret_key == _INSECURE_DEFAULT_KEY:
            raise RuntimeError(
                "ZUUL_SECRET_KEY must be set to a secure value in "
                f"'{self.environment}' environment. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        if self.environment != "development":
            _default_salts = {
                "ZUUL_VAULT_SALT": (self.vault_salt, "zuultimate-vault-v2"),
                "ZUUL_MFA_SALT": (self.mfa_salt, "zuultimate-mfa-secret"),
                "ZUUL_PASSWORD_VAULT_SALT": (self.password_vault_salt, "zuultimate-pw-vault"),
            }
            for env_var, (current, default) in _default_salts.items():
                if current == default:
                    raise RuntimeError(
                        f"{env_var} must be set to a unique value in "
                        f"'{self.environment}' environment. "
                        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
                    )
            db_urls = {
                "ZUUL_IDENTITY_DB_URL": self.identity_db_url,
                "ZUUL_CREDENTIAL_DB_URL": self.credential_db_url,
                "ZUUL_SESSION_DB_URL": self.session_db_url,
                "ZUUL_TRANSACTION_DB_URL": self.transaction_db_url,
                "ZUUL_AUDIT_DB_URL": self.audit_db_url,
                "ZUUL_CRM_DB_URL": self.crm_db_url,
            }
            for env_var, url in db_urls.items():
                if "sqlite" in url:
                    warnings.warn(
                        f"{env_var} contains 'sqlite' — use PostgreSQL for production",
                        UserWarning,
                        stacklevel=2,
                    )
            if "localhost" in self.redis_url:
                warnings.warn(
                    "ZUUL_REDIS_URL contains 'localhost' — use a dedicated Redis host for production",
                    UserWarning,
                    stacklevel=2,
                )
            for origin in self.cors_origins:
                if "localhost" in origin:
                    warnings.warn(
                        f"ZUUL_CORS_ORIGINS contains 'localhost' ({origin}) — "
                        "use production domains only",
                        UserWarning,
                        stacklevel=2,
                    )
                    break
        if self.secret_key == _INSECURE_DEFAULT_KEY:
            warnings.warn(
                "Using default insecure secret key — set ZUUL_SECRET_KEY for production",
                UserWarning,
                stacklevel=2,
            )


PLAN_ENTITLEMENTS: dict[str, list[str]] = {
    "free": [
        "trendscope:basic",
        "shopforge:basic",
        "brandguard:basic",
        "taskpilot:basic",
        "sentinel:basic",
        "shandorcode:basic",
    ],
    "pro": [
        "trendscope:full",
        "shopforge:full",
        "brandguard:full",
        "taskpilot:full",
        "sentinel:full",
        "shandorcode:full",
        "nexus:basic",
        "claude_swarm:basic",
        "gpu_orchestra:basic",
        "knowledge_harvester:basic",
    ],
    "growth": [
        "trendscope:full",
        "shopforge:full",
        "brandguard:full",
        "taskpilot:full",
        "sentinel:full",
        "shandorcode:full",
        "nexus:full",
        "claude_swarm:full",
        "gpu_orchestra:full",
        "knowledge_harvester:full",
        "agentwerk:full",
        "white_label",
    ],
    "scale": [
        "trendscope:full",
        "shopforge:full",
        "brandguard:full",
        "taskpilot:full",
        "sentinel:full",
        "shandorcode:full",
        "nexus:full",
        "claude_swarm:full",
        "gpu_orchestra:full",
        "knowledge_harvester:full",
        "agentwerk:full",
        "white_label",
        "sso_saml",
        "sla_guarantee",
        "custom_integrations",
    ],
}

# Backward compatibility aliases
PLAN_ENTITLEMENTS["starter"] = PLAN_ENTITLEMENTS["free"]
PLAN_ENTITLEMENTS["business"] = PLAN_ENTITLEMENTS["growth"]
PLAN_ENTITLEMENTS["enterprise"] = PLAN_ENTITLEMENTS["scale"]

# Credit allocations per plan tier
PLAN_CREDITS: dict[str, int] = {
    "free": 0,
    "starter": 0,
    "pro": 5_000,
    "growth": 25_000,
    "scale": 80_000,
}

# Backward compatibility aliases
PLAN_CREDITS["business"] = PLAN_CREDITS["growth"]
PLAN_CREDITS["enterprise"] = PLAN_CREDITS["scale"]


@lru_cache
def get_settings() -> ZuulSettings:
    settings = ZuulSettings()
    settings.validate_for_production()
    return settings
